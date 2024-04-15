use emacs::{defun, Env, FromLisp, IntoLisp, Result, Value};
use std::cell::RefCell;
use std::collections::HashMap;
use std::io::{Read, Seek, SeekFrom, Write};
use std::rc::Rc;

emacs::plugin_is_GPL_compatible!();

use anyhow::bail;
use libssh_rs::*;

thread_local! {
    static SESSIONS: RefCell<HashMap<String, Rc<Session>>> = RefCell::new(HashMap::new());
}

const BLOCKSIZE: usize = 163840;

emacs::use_symbols! {
    nil t
    car cdr nth cons nreverse
    tramp_dissect_file_name
    read_passwd read_string
    insert replace_buffer_contents
    set_buffer current_buffer generate_new_buffer kill_buffer
    buffer_substring_no_properties
    buffer_size
    string_match_p
}

#[emacs::module(name = "tramp-libssh")]
fn init(_: &Env) -> Result<()> {
    Ok(())
}

struct DissectedFilename {
    full_name: String,
    protocol: String,
    user: String,
    host: String,
    filename: String,
}

trait LocalEnv<'a> {
    fn nil(&self) -> Value<'a>;
    fn t(&self) -> Value<'a>;
    fn car(&self, list: Value<'a>) -> Result<Value<'a>>;
    fn cdr(&self, list: Value<'a>) -> Result<Value<'a>>;
    fn nth(&self, idx: usize, list: Value<'a>) -> Result<Value<'a>>;
    fn cons(&self, car_v: Value<'a>, cdr_v: Value<'a>) -> Result<Value<'a>>;
    fn nreverse(&self, list: Value<'a>) -> Result<Value<'a>>;
    fn tramp_dissect_file_name_el(&self, filename: Value<'a>) -> Result<Value<'a>>;
    fn tramp_dissect_file_name(&self, filename: Value<'a>) -> Result<DissectedFilename>;
    fn read_passwd(&self, prompt: &str, confirm: bool) -> Result<String>;
    fn read_string(&self, prompt: &str) -> Result<String>;
    fn insert(&self, text: &str) -> Result<()>;
    fn replace_buffer_contents(&self, other_buf: Value<'a>) -> Result<()>;
    fn set_buffer(&self, buffer: Value<'a>) -> Result<()>;
    fn current_buffer(&self) -> Result<Value<'a>>;
    fn generate_new_buffer(&self, name: &str) -> Result<Value<'a>>;
    fn kill_buffer(&self, buffer: Value<'a>) -> Result<()>;
    fn buffer_substring_no_properties(&self, start: usize, end: usize) -> Result<String>;
    fn buffer_size(&self) -> Result<usize>;
    fn default_directory(&self) -> Result<DissectedFilename>;
    fn string_match_p(&self, regexp: Value<'a>, match_string: &str) -> Result<bool>;
}

impl<'a> LocalEnv<'a> for &'a Env {
    fn nil(&self) -> Value<'a> {
        nil.bind(self)
    }

    fn t(&self) -> Value<'a> {
        t.bind(self)
    }

    fn car(&self, list: Value<'a>) -> Result<Value<'a>> {
        self.call(car, &[list])
    }

    fn cdr(&self, list: Value<'a>) -> Result<Value<'a>> {
        self.call(cdr, &[list])
    }

    fn nth(&self, idx: usize, list: Value<'a>) -> Result<Value<'a>> {
        self.call(nth, &[idx.into_lisp(self)?, list])
    }

    fn cons(&self, car_v: Value<'a>, cdr_v: Value<'a>) -> Result<Value<'a>> {
        self.call(cons, &[car_v, cdr_v])
    }

    fn nreverse(&self, list: Value<'a>) -> Result<Value<'a>> {
        self.call(nreverse, &[list])
    }

    fn tramp_dissect_file_name_el(&self, filename: Value<'a>) -> Result<Value<'a>> {
        self.call(tramp_dissect_file_name, &[filename])
    }

    fn tramp_dissect_file_name(&self, filename: Value<'a>) -> Result<DissectedFilename> {
        let dissected_v = self.tramp_dissect_file_name_el(filename)?;

        Ok(DissectedFilename {
            full_name: String::from_lisp(filename)?,
            protocol: String::from_lisp(self.nth(1, dissected_v)?)?,
            user: String::from_lisp(self.nth(2, dissected_v)?)?,
            host: String::from_lisp(self.nth(4, dissected_v)?)?,
            filename: String::from_lisp(self.nth(6, dissected_v)?)?,
        })
    }

    fn read_passwd(&self, prompt: &str, confirm: bool) -> Result<String> {
        let confirm = if confirm { t } else { nil };
        let passwd_v = self.call(read_passwd, &[prompt.into_lisp(self)?, confirm.bind(self)])?;
        String::from_lisp(passwd_v)
    }

    fn read_string(&self, prompt: &str) -> Result<String> {
        let result_v = self.call(read_string, &[prompt.into_lisp(self)?])?;
        String::from_lisp(result_v)
    }

    fn insert(&self, text: &str) -> Result<()> {
        self.call(insert, &[text.into_lisp(self)?])?;
        Ok(())
    }

    fn replace_buffer_contents(&self, other_buf: Value<'a>) -> Result<()> {
        self.call(replace_buffer_contents, &[other_buf])?;
        Ok(())
    }

    fn set_buffer(&self, buffer: Value<'a>) -> Result<()> {
        self.call(set_buffer, &[buffer])?;
        Ok(())
    }

    fn current_buffer(&self) -> Result<Value<'a>> {
        self.call(current_buffer, &[])
    }

    fn generate_new_buffer(&self, name: &str) -> Result<Value<'a>> {
        self.call(generate_new_buffer, &[name.into_lisp(self)?])
    }

    fn kill_buffer(&self, buffer: Value<'a>) -> Result<()> {
        self.call(kill_buffer, &[buffer])?;
        Ok(())
    }

    fn buffer_substring_no_properties(&self, begin: usize, end: usize) -> Result<String> {
        String::from_lisp(self.call(
            buffer_substring_no_properties,
            &[begin.into_lisp(self)?, end.into_lisp(self)?],
        )?)
    }

    fn buffer_size(&self) -> Result<usize> {
        usize::from_lisp(self.call(buffer_size, &[])?)
    }

    fn default_directory(&self) -> Result<DissectedFilename> {
        self.tramp_dissect_file_name(self.intern("default-directory")?)
    }

    fn string_match_p(&self, regexp: Value<'a>, match_string: &str) -> Result<bool> {
        let result = self.call(string_match_p, &[regexp, match_string.into_lisp(self)?])?;
        Ok(result.is_not_nil())
    }
}

fn get_connection(user: &str, host: &str, env: &Env) -> Result<Rc<Session>> {
    let connection_str = format!("{}@{}", user, host);
    SESSIONS.with(|sessions| {
        let mut sessions = sessions.try_borrow_mut()?;
        if let Some(session) = sessions.get(&connection_str) {
            if session.is_connected() {
                env.message("Cached session")?;
                Ok(session.clone())
            } else {
                let session = Rc::new(init_connection(user, host, env)?);
                sessions.insert(connection_str, session.clone());
                Ok(session)
            }
        } else {
            let session = Rc::new(init_connection(user, host, env)?);
            sessions.insert(connection_str, session.clone());
            Ok(session)
        }
    })
}

fn init_connection(user: &str, host: &str, env: &Env) -> Result<Session> {
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
        }
        KnownHosts::Other => {
            bail!(format!(
                "Host key for server {} not found but other type of key exists",
                host
            ));
        }
        KnownHosts::NotFound => {
            bail!("Known hosts file not found");
        }
        KnownHosts::Unknown => {
            bail!(format!("Server {} unknown", host));
        }
        KnownHosts::Ok => {}
    }

    session.userauth_public_key_auto(None, None)?;
    env.message("Connected session")?;

    Ok(session)
}

#[defun]
fn write_region(
    env: &Env,
    start: Option<Value>,
    end: Option<Value>,
    filename: Value,
    append: Option<Value>,
    visit: Option<Value>,
    lockname: Option<Value>,
    mustbenew: Option<Value>,
) -> Result<()> {
    let dissected = env.tramp_dissect_file_name(filename)?;

    let (str_contents, begin) = if let Some(start) = start {
        (
            String::from_lisp(start).ok(),
            usize::from_lisp(start).unwrap_or(0),
        )
    } else {
        (None, 0)
    };

    let end = if !str_contents.is_none() {
        str_contents.as_ref().unwrap().len()
    } else if start.is_none() || end.is_none() {
        env.buffer_size()?
    } else {
        usize::from_lisp(end.unwrap())?
    };

    let (seek, append_file) = if let Some(append_val) = append {
        if let Some(seek) = u64::from_lisp(append_val).ok() {
            (Some(seek), false)
        } else {
            (None, true)
        }
    } else {
        (None, false)
    };

    let session = get_connection(&dissected.user, &dissected.host, &env)?;
    let sftp_sess = session.sftp()?;
    let mut open_mode = OpenFlags::READ_ONLY | OpenFlags::CREATE;
    if append_file {
        open_mode |= OpenFlags::APPEND;
    } else if begin == 0 {
        open_mode |= OpenFlags::TRUNCATE;
    }
    let mut rfile = sftp_sess.open(&dissected.filename, open_mode, 0o644)?;

    if !append_file {
        if let Some(seek) = seek {
            rfile.seek(SeekFrom::Start(seek))?;
        }
    }

    if let Some(str_contents) = str_contents {
        rfile.write(str_contents.as_bytes())?;
    } else {
        let mut cur_byte = begin + 1;

        loop {
            let substring_end = if end - cur_byte > BLOCKSIZE {
                cur_byte + BLOCKSIZE
            } else {
                end
            };

            let bufstring = env.buffer_substring_no_properties(cur_byte, substring_end)?;
            let written = rfile.write(bufstring.as_bytes())?;
            cur_byte += written;

            if cur_byte == end {
                break;
            } else if cur_byte > end {
                bail!("Wrote too much?");
            }
        }
    }

    Ok(())
}

#[defun]
fn insert_file_contents1(
    env: &Env,
    filename: Value,
    visit: Option<Value>,
    begin: Option<usize>,
    end: Option<usize>,
    replace: Option<Value>,
) -> Result<()> {
    let dissected = env.tramp_dissect_file_name(filename)?;
    let session = get_connection(&dissected.user, &dissected.host, &env)?;

    let sftp_sess = session.sftp()?;
    let mut rfile = sftp_sess.open(&dissected.filename, OpenFlags::READ_ONLY, 0)?;
    if let Some(off) = begin {
        rfile.seek(SeekFrom::Start(off as u64))?;
    }

    let (orig_buf, tmp_buf) = if let Some(_) = replace {
        let tmp_buf = env.generate_new_buffer("*tmp*")?;
        let orig_buf = env.current_buffer()?;
        env.set_buffer(tmp_buf)?;
        (orig_buf, tmp_buf)
    } else {
        (env.nil(), env.nil())
    };

    let mut total_bytes: usize = 0;
    let mut buf = [0; BLOCKSIZE];
    loop {
        let bufslice: &mut [u8] = if let Some(end) = end {
            if total_bytes >= end {
                break;
            }

            let remaining: usize = end - total_bytes;
            if remaining < BLOCKSIZE {
                &mut buf[0..remaining]
            } else {
                &mut buf[..]
            }
        } else {
            &mut buf[..]
        };

        let bytes = rfile.read(bufslice)?;
        if bytes == 0 {
            break;
        }

        env.insert(&std::str::from_utf8(&buf[0..bytes])?)?;

        total_bytes += bytes;
    }

    if let Some(_) = replace {
        env.set_buffer(orig_buf)?;
        env.replace_buffer_contents(tmp_buf)?;
        env.kill_buffer(tmp_buf)?;
    }

    Ok(())
}

#[defun]
fn file_exists_p<'a>(env: &'a Env, filename: Value<'a>) -> Result<Value<'a>> {
    let dissected = env.tramp_dissect_file_name(filename)?;
    let session = get_connection(&dissected.user, &dissected.host, &env)?;
    let sftp = session.sftp()?;
    let res = sftp.open(&dissected.filename, OpenFlags::READ_ONLY, 0);
    match res {
        Ok(_) => Ok(t.bind(env)),
        Err(libssh_rs::Error::Sftp(e)) => {
            let e: std::io::Error = e.into();
            match e.kind() {
                std::io::ErrorKind::NotFound => Ok(nil.bind(env)),
                _ => Err(e.into()),
            }
        }
        Err(e) => Err(e.into()),
    }
}

#[defun]
fn directory_files<'a>(
    env: &'a Env,
    directory: Value<'a>,
    full_name: Option<Value<'a>>,
    match_regexp: Option<Value<'a>>,
    nosort: Option<Value<'a>>,
    count: Option<usize>,
) -> Result<Value<'a>> {
    let dissected = env.tramp_dissect_file_name(directory)?;
    let session = get_connection(&dissected.user, &dissected.host, &env)?;
    let sftp = session.sftp()?;
    let dir = sftp.open_dir(&dissected.filename)?;
    let mut dirlist: Value<'a> = nil.bind(env);

    let full_dir = if dissected.filename.ends_with("/") {
        dissected.filename
    } else {
        dissected.filename.clone() + "/"
    };

    let mut counter = 0;
    loop {
        if let Some(count) = count {
            if counter >= count {
                break;
            }
            counter += 1;
        }

        match dir.read_dir().transpose()? {
            Some(attributes) => {
                let short_name = attributes.name().unwrap();

                if let Some(match_regexp) = match_regexp {
                    if !env.string_match_p(match_regexp, short_name)? {
                        continue;
                    }
                };

                let name = match full_name {
                    Some(_) => full_dir.clone() + short_name,
                    None => short_name.to_string(),
                };
                dirlist = env.cons(name.into_lisp(env)?, dirlist)?
            }
            None => break,
        }
    }

    if nosort.is_some() {
        Ok(dirlist)
    } else {
        env.nreverse(dirlist)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {}
}
