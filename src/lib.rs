use std::cell::RefCell;
use std::rc::Rc;
use emacs::{defun, CallEnv, Env, IntoLisp, Result, Value, FromLisp};

emacs::plugin_is_GPL_compatible!();

use libssh_rs::{*, sys::{SSH_ADDRSTRLEN, sftp_init}};
use anyhow::bail;
use libc::O_RDONLY;
use std::io::Read;

/*thread_local! {
    static SESSIONS: RefCell<HashMap<String, Session>>;
}*/

#[emacs::module(name = "tramp-libssh")]
fn init(_: &Env) -> Result<()> { Ok(()) }

struct LocalEnv<'a> {
    pub env: &'a Env,
    nil_v: Value<'a>,
    t_v: Value<'a>,
    car_v: Value<'a>,
    cdr_v: Value<'a>,
    nth_v: Value<'a>,
    tramp_dissect_file_name_v: Value<'a>,
    read_passwd_v: Value<'a>,
    read_string_v: Value<'a>,
    insert_v: Value<'a>,
}

struct DissectedFilename {
    protocol: String,
    user: String,
    host: String,
    filename: String,
}

impl<'a> LocalEnv<'a> {
    pub fn new(env: &'a Env) -> Result<Self> {
        Ok(Self {
            env: env,
            nil_v: env.intern("nil")?,
            t_v: env.intern("t")?,
            car_v: env.intern("car")?,
            cdr_v: env.intern("cdr")?,
            nth_v: env.intern("nth")?,
            tramp_dissect_file_name_v: env.intern("tramp-dissect-file-name")?,
            read_passwd_v: env.intern("read-passwd")?,
            read_string_v: env.intern("read-string")?,
            insert_v: env.intern("insert")?,
        })
    }

    pub fn nil(&self) -> Value<'a> {
        self.nil_v.clone()
    }

    pub fn car(&self, list: Value<'a>) -> Result<Value<'a>> {
        self.env.call(self.car_v, &[list])
    }

    pub fn cdr(&self, list: Value<'a>) -> Result<Value<'a>> {
        self.env.call(self.cdr_v, &[list])
    }
    
    pub fn nth(&self, idx: usize, list: Value<'a>) -> Result<Value<'a>> {
        self.env.call(self.nth_v, &[idx.into_lisp(self.env)?, list])
    }

    pub fn tramp_dissect_file_name_el(&self, filename: Value<'a>) -> Result<Value<'a>> {
        self.env.call(self.tramp_dissect_file_name_v, &[filename])
    }

    pub fn message(&self, msg: &str) -> Result<Value<'a>> {
        self.env.message(msg)
    }

    pub fn intern(&self, symbol: &str) -> Result<Value<'a>> {
        self.env.intern(symbol)
    }

    pub fn tramp_dissect_file_name(&self, filename: Value<'a>) -> Result<DissectedFilename> {
        self.env.message("dissecting")?;
        let dissected_v = self.tramp_dissect_file_name_el(filename)?;
        self.env.message("extracting")?;
        
        Ok(
            DissectedFilename {
                protocol: String::from_lisp(self.nth(1, dissected_v)?)?,
                user: String::from_lisp(self.nth(2, dissected_v)?)?,
                host: String::from_lisp(self.nth(4, dissected_v)?)?,
                filename: String::from_lisp(self.nth(6, dissected_v)?)?,
            }
        )
    }

    pub fn read_passwd(&self, prompt: &str, confirm: bool) -> Result<String> {
        let confirm = if confirm {
            self.t_v
        } else {
            self.nil_v
        };
        let passwd_v = self.env.call(self.read_passwd_v, &[prompt.into_lisp(self.env)?, confirm])?;
        String::from_lisp(passwd_v)
    }

    pub fn read_string(&self, prompt: &str) -> Result<String> {
        let result_v = self.env.call(self.read_string_v, &[prompt.into_lisp(self.env)?])?;
        String::from_lisp(result_v)
    }

    pub fn insert(&self, text: &str) -> Result<()> {
        self.env.call(self.insert_v, &[text.into_lisp(&self.env)?])?;
        Ok(())
    }
}

fn get_connection(user: &str, host: &str, env: &LocalEnv) -> Result<Session> {
    let session = Session::new()?;
    /*unsafe {
        //let env: *const LocalEnv = env as *const LocalEnv;
        session.set_auth_callback(
            |prompt, echo, verify, identity|
            env.borrow().read_passwd(prompt, verify).map_err(|e| libssh_rs::Error::Fatal(e.to_string()))
        );
    }*/
    session.set_option(SshOption::User(Some(user.to_string())))?;
    session.set_option(SshOption::Hostname(host.to_string()))?;
    session.options_parse_config(None)?;
    session.connect()?;
    let srv_pubkey = session.get_server_public_key()?;
    let hash = srv_pubkey.get_public_key_hash(PublicKeyHashType::Sha1)?;
    match session.is_known_server()? {
        KnownHosts::Changed => {
            bail!(format!("Host key for server {} changed", host));
        },
        KnownHosts::Other => {
            bail!(format!("Host key for server {} not found but other type of key exists", host));
        },
        KnownHosts::NotFound => {
            bail!("Known hosts file not found");
            
        },
        KnownHosts::Unknown => {
            bail!(format!("Server {} unknown", host));
        },
        KnownHosts::Ok => {}
    }

    session.userauth_public_key_auto(None, None)?;

    Ok(session)
}

#[defun]
fn insert_file_contents1(env: &Env, filename: Value, visit: Option<Value>, begin: Option<i64>, end: Option<i64>, replace: Option<Value>) -> Result<()> {
    let env = LocalEnv::new(env)?;
    env.message("insert-file-contents3")?;
    let dissected = env.tramp_dissect_file_name(filename)?;
    env.message("formatting")?;
    env.message(&format!("filename {} has username {} host {} and file {}", String::from_lisp(filename)?, dissected.user, dissected.host, dissected.filename))?;

    let session = get_connection(&dissected.user, &dissected.host, &env)?;
    env.message("Connected session")?;

    let sftp_sess = session.sftp()?;
    let mut rfile = sftp_sess.open(&dissected.filename, O_RDONLY, 0)?;

    loop {
        let mut buf = [0; 16384];

        let bytes = rfile.read(&mut buf)?;
        if bytes == 0 {
            break;
        }
        
        env.insert(&std::str::from_utf8(&buf[0 .. bytes])?)?;
    }
        
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
    }
}
