use emacs::Error as EmacsError;
use emacs::Result as EmacsResult;
use emacs::{defun, Env, FromLisp, IntoLisp, Value};
use libssh_rs::Error as SshError;
use std::cell::BorrowMutError;
use std::cell::RefCell;
use std::collections::HashMap;
use std::fs::File;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::io;
use std::io::Error as IOError;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::rc::Rc;
use std::str::Utf8Error;
use std::time::SystemTime;
use thiserror::Error;
//use pipe::{pipe, PipeReader, PipeWriter};
//use crossbeam_channel::{unbounded as channel};

emacs::plugin_is_GPL_compatible!();

use anyhow::{anyhow, bail, Context};
use libssh_rs::*;

struct ScopedStatic<Inner> {
    inner: RefCell<Option<*const Inner>>,
}

impl<Inner> Default for ScopedStatic<Inner> {
    fn default() -> Self {
        Self {
            inner: RefCell::new(None),
        }
    }
}

impl<Inner> ScopedStatic<Inner> {
    pub fn scope<'a, Ret>(&self, scoped: &'a Inner, f: impl FnOnce() -> Ret) -> Ret {
        {
            let scoped_ptr: *const Inner = scoped;
            let mut inner = self.inner.borrow_mut();
            *inner = Some(scoped_ptr);
        }

        let ret = f();

        {
            let mut inner = self.inner.borrow_mut();
            *inner = None
        }

        ret
    }

    pub fn borrow<'a>(&self) -> EmacsResult<&'a Inner> {
        unsafe {
            self.inner
                .borrow()
                .ok_or(anyhow!("Not scoped"))?
                .as_ref()
                .ok_or(anyhow!("inner invalid"))
        }
    }
}

/*struct AsyncSession {
    signal_pipe: PipeWriter,
    control: crossbeam_channel::Sender<ControlMsg>,
    response: crossbeam_channel::Rec
}*/

thread_local! {
    static SESSIONS: RefCell<HashMap<String, Rc<Session>>> = RefCell::new(HashMap::new());
    static SFTPS: RefCell<HashMap<String, Rc<Sftp>>> = RefCell::new(HashMap::new());
    //static ASYNC_SESSIONS: RefCell<HashMap<String, Rc<AsyncSession>>> = RefCell::new(HashMap::new());
    static CURRENT_ENV: ScopedStatic<Env> = ScopedStatic::default();
}

const BLOCKSIZE: usize = 163840;
const RETRIES: usize = 5;

emacs::use_symbols! {
    nil t
    car cdr nth cons nreverse
    tramp_dissect_file_name
    read_passwd read_string y_or_n_p
    insert replace_buffer_contents
    set_buffer current_buffer generate_new_buffer kill_buffer get_buffer_create
    buffer_substring_no_properties
    buffer_size
    string_match_p
        string integer
        eval
        expand_file_name
        get_t
}

#[emacs::module(name = "tramp-libssh")]
fn init(_: &Env) -> EmacsResult<()> {
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
    fn car(&self, list: Value<'a>) -> EmacsResult<Value<'a>>;
    fn cdr(&self, list: Value<'a>) -> EmacsResult<Value<'a>>;
    fn nth(&self, idx: usize, list: Value<'a>) -> EmacsResult<Value<'a>>;
    fn cons(&self, car_v: Value<'a>, cdr_v: Value<'a>) -> EmacsResult<Value<'a>>;
    fn nreverse(&self, list: Value<'a>) -> EmacsResult<Value<'a>>;
    fn tramp_dissect_file_name_el(&self, filename: Value<'a>) -> EmacsResult<Value<'a>>;
    fn tramp_dissect_file_name(&self, filename: Value<'a>) -> EmacsResult<DissectedFilename>;
    fn read_passwd(&self, prompt: &str, confirm: bool) -> EmacsResult<String>;
    fn read_string(&self, prompt: &str) -> EmacsResult<String>;
    fn y_or_n_p(&self, prompt: &str) -> EmacsResult<bool>;
    fn insert(&self, text: &str) -> EmacsResult<()>;
    fn replace_buffer_contents(&self, other_buf: Value<'a>) -> EmacsResult<()>;
    fn set_buffer(&self, buffer: Value<'a>) -> EmacsResult<()>;
    fn current_buffer(&self) -> EmacsResult<Value<'a>>;
    fn generate_new_buffer(&self, name: &str) -> EmacsResult<Value<'a>>;
    fn get_buffer_create(&self, buffer_or_name: Value<'a>) -> EmacsResult<Value<'a>>;
    fn kill_buffer(&self, buffer: Value<'a>) -> EmacsResult<()>;
    fn buffer_substring_no_properties(&self, start: usize, end: usize) -> EmacsResult<String>;
    fn buffer_size(&self) -> EmacsResult<usize>;
    fn default_directory(&self) -> EmacsResult<DissectedFilename>;
    fn string_match_p(&self, regexp: Value<'a>, match_string: &str) -> EmacsResult<bool>;
    fn build_list(&self, values: &[Value<'a>]) -> EmacsResult<Value<'a>>;
    fn eval(&self, text: &str) -> EmacsResult<Value<'a>>;
    fn expand_file_name(&self, filename: &str) -> EmacsResult<Value<'a>>;
}

impl<'a> LocalEnv<'a> for &'a Env {
    fn nil(&self) -> Value<'a> {
        nil.bind(self)
    }

    fn t(&self) -> Value<'a> {
        t.bind(self)
    }

    fn car(&self, list: Value<'a>) -> EmacsResult<Value<'a>> {
        self.call(car, &[list])
    }

    fn cdr(&self, list: Value<'a>) -> EmacsResult<Value<'a>> {
        self.call(cdr, &[list])
    }

    fn nth(&self, idx: usize, list: Value<'a>) -> EmacsResult<Value<'a>> {
        self.call(nth, &[idx.into_lisp(self)?, list])
    }

    fn cons(&self, car_v: Value<'a>, cdr_v: Value<'a>) -> EmacsResult<Value<'a>> {
        self.call(cons, &[car_v, cdr_v])
    }

    fn nreverse(&self, list: Value<'a>) -> EmacsResult<Value<'a>> {
        self.call(nreverse, &[list])
    }

    fn tramp_dissect_file_name_el(&self, filename: Value<'a>) -> EmacsResult<Value<'a>> {
        self.call(tramp_dissect_file_name, &[filename.clone()])
    }

    fn tramp_dissect_file_name(&self, filename: Value<'a>) -> EmacsResult<DissectedFilename> {
        let dissected_v = self.tramp_dissect_file_name_el(filename)?;

        Ok(DissectedFilename {
            full_name: String::from_lisp(filename)?,
            protocol: String::from_lisp(self.nth(1, dissected_v)?)?,
            user: String::from_lisp(self.nth(2, dissected_v)?)?,
            host: String::from_lisp(self.nth(4, dissected_v)?)?,
            filename: String::from_lisp(self.nth(6, dissected_v)?)?,
        })
    }

    fn read_passwd(&self, prompt: &str, confirm: bool) -> EmacsResult<String> {
        let confirm = if confirm { t } else { nil };
        let passwd_v = self.call(read_passwd, &[prompt.into_lisp(self)?, confirm.bind(self)])?;
        String::from_lisp(passwd_v)
    }

    fn read_string(&self, prompt: &str) -> EmacsResult<String> {
        let result_v = self.call(read_string, &[prompt.into_lisp(self)?])?;
        String::from_lisp(result_v)
    }

    fn y_or_n_p(&self, prompt: &str) -> EmacsResult<bool> {
        let result_v = self.call(y_or_n_p, &[prompt.into_lisp(self)?])?;
        Ok(result_v.is_not_nil())
    }

    fn insert(&self, text: &str) -> EmacsResult<()> {
        self.call(insert, &[text.into_lisp(self)?])?;
        Ok(())
    }

    fn replace_buffer_contents(&self, other_buf: Value<'a>) -> EmacsResult<()> {
        self.call(replace_buffer_contents, &[other_buf])?;
        Ok(())
    }

    fn set_buffer(&self, buffer: Value<'a>) -> EmacsResult<()> {
        self.call(set_buffer, &[buffer])?;
        Ok(())
    }

    fn current_buffer(&self) -> EmacsResult<Value<'a>> {
        self.call(current_buffer, &[])
    }

    fn generate_new_buffer(&self, name: &str) -> EmacsResult<Value<'a>> {
        self.call(generate_new_buffer, &[name.into_lisp(self)?])
    }

    fn kill_buffer(&self, buffer: Value<'a>) -> EmacsResult<()> {
        self.call(kill_buffer, &[buffer])?;
        Ok(())
    }

    fn buffer_substring_no_properties(&self, begin: usize, end: usize) -> EmacsResult<String> {
        String::from_lisp(self.call(
            buffer_substring_no_properties,
            &[begin.into_lisp(self)?, end.into_lisp(self)?],
        )?)
    }

    fn buffer_size(&self) -> EmacsResult<usize> {
        usize::from_lisp(self.call(buffer_size, &[])?)
    }

    fn get_buffer_create(&self, buffer_or_name: Value<'a>) -> EmacsResult<Value<'a>> {
        self.call(get_buffer_create, &[buffer_or_name])
    }

    fn default_directory(&self) -> EmacsResult<DissectedFilename> {
        self.tramp_dissect_file_name(self.expand_file_name(".")?)
    }

    fn string_match_p(&self, regexp: Value<'a>, match_string: &str) -> EmacsResult<bool> {
        let result = self.call(string_match_p, &[regexp, match_string.into_lisp(self)?])?;
        Ok(result.is_not_nil())
    }

    fn build_list(&self, values: &[Value<'a>]) -> EmacsResult<Value<'a>> {
        let mut result = nil.bind(self);
        for val in values.into_iter().rev() {
            result = self.cons(*val, result)?;
        }
        Ok(result)
    }

    fn eval(&self, text: &str) -> EmacsResult<Value<'a>> {
        self.call(eval, &[text.into_lisp(self)?])
    }

    fn expand_file_name(&self, filename: &str) -> EmacsResult<Value<'a>> {
        self.call(expand_file_name, &[filename.into_lisp(self)?])
    }
}

// Get around foreign type rule
trait MyIntoLisp<'e> {
    fn into_lisp(self, env: &'e Env) -> EmacsResult<Value<'e>>;
}

impl<'e> MyIntoLisp<'e> for SystemTime {
    fn into_lisp(self, env: &'e Env) -> EmacsResult<Value<'e>> {
        let dur = self.duration_since(SystemTime::UNIX_EPOCH)?;
        let s = dur.as_secs();
        let ns = dur.subsec_nanos();

        // ported from timefns.c make_lisp_time()
        let lo_time_bits = 16;
        let hi_time = (s >> lo_time_bits).into_lisp(env)?;
        let lo_time = (s & ((1 << lo_time_bits) - 1)).into_lisp(env)?;
        let micro = (ns / 1000).into_lisp(env)?;
        let pico = (ns % 1000 * 1000).into_lisp(env)?;

        let timestamp = env.build_list(&[hi_time, lo_time, micro, pico])?;
        Ok(timestamp)
    }
}

struct ValueIterator<'e>(Value<'e>);

impl<'e> Iterator for ValueIterator<'e> {
    type Item = EmacsResult<Value<'e>>;
    fn next(&mut self) -> Option<Self::Item> {
        let car_v: Value<'e> = match self.0.car() {
            Ok(car_v) => car_v,
            Err(e) => return Some(Err(e)),
        };
        if car_v.is_not_nil() {
            self.0 = match self.0.cdr() {
                Ok(cdr_v) => cdr_v,
                Err(e) => return Some(Err(e)),
            };

            return Some(Ok(car_v));
        } else {
            return None;
        }
    }
}

trait ValueExt<'e> {
    fn cons(self, cdr_v: impl IntoLisp<'e>) -> EmacsResult<Value<'e>>;
    fn iter(self) -> ValueIterator<'e>;
}

impl<'e> ValueExt<'e> for Value<'e> {
    fn cons(self, cdr_v: impl IntoLisp<'e>) -> EmacsResult<Value<'e>> {
        self.env.cons(cdr_v.into_lisp(self.env)?, self)
    }

    fn iter(self) -> ValueIterator<'e> {
        ValueIterator(self)
    }
}

fn ssh_auth_callback(
    prompt: &str,
    echo: bool,
    verify: bool,
    identity: Option<String>,
) -> SshResult<String> {
    CURRENT_ENV
        .with(|current_env| {
            let prompt = match identity {
                Some(ident) => format!("{} ({}): ", prompt, ident),
                None => prompt.to_string(),
            };

            let env = current_env.borrow()?;
            if echo {
                let password = env.read_string(&prompt)?;
                if verify {
                    let password2 = env.read_string(&prompt)?;
                    if password != password2 {
                        bail!("Passwords don't match")
                    }
                }
                Ok(password)
            } else {
                env.read_passwd(&prompt, verify)
            }
        })
        .map_err(|e: anyhow::Error| SshError::Fatal(e.to_string()))
}

fn get_connection(user: &str, host: &str, env: &Env) -> HandlerResult<Rc<Session>> {
    let connection_str = format!("{}@{}", user, host);
    SESSIONS.with(|sessions| {
        let mut sessions = sessions.try_borrow_mut()?;
        if let Some(session) = sessions.get(&connection_str) {
            if session.is_connected() {
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

fn get_sftp(user: &str, host: &str, session: &Session) -> EmacsResult<Rc<Sftp>> {
    let connection_str = format!("{}@{}", user, host);
    SFTPS.with(|sftps| {
        let mut sftps = sftps.try_borrow_mut()?;
        if let Some(sftp) = sftps.get(&connection_str) {
            Ok(sftp.clone())
        } else {
            let sftp = Rc::new(session.sftp()?);
            sftps.insert(connection_str, sftp.clone());
            Ok(sftp)
        }
    })
}

fn init_connection(user: &str, host: &str, env: &Env) -> EmacsResult<Session> {
    let session = Session::new()?;
    session.set_option(SshOption::User(Some(user.to_string())))?;
    session.set_option(SshOption::Hostname(host.to_string()))?;
    session.options_parse_config(None)?;
    session.set_auth_callback(ssh_auth_callback);

    CURRENT_ENV.with(|current_env| {
        current_env.scope(env, || {
            session.connect()?;
            //let srv_pubkey = session.get_server_public_key()?;
            //let hash = srv_pubkey.get_public_key_hash(PublicKeyHashType::Sha1)?;
            match session.is_known_server()? {
                KnownHosts::Changed => {
                    bail!(format!(
                        "Host key for server {} changed, remove from known hosts to update",
                        host
                    ));
                }
                KnownHosts::Other => {
                    bail!(format!(
                        "Host key for server {} not found but other type of key exists",
                        host
                    ));
                }
                KnownHosts::NotFound | KnownHosts::Unknown => {
                    let trust =
                        env.y_or_n_p(&format!("SSH host {} not known. Trust host key?: ", host))?;
                    if trust {
                        session.update_known_hosts_file()?;
                    } else {
                        bail!(format!("Host {} not trusted", host));
                    }
                }
                KnownHosts::Ok => {}
            }

            session.userauth_public_key_auto(None, None)?;
            //let password = env.read_passwd(&format!("Password ({}@{}): ", user, host), false)?;
            //session.userauth_password(Some(&user), Some(&password))?;
            env.message("Connected session")?;

            Ok(session)
        })
    })
}

#[derive(Error, Debug)]
enum HandlerError {
    #[error("{0}")]
    Emacs(#[from] EmacsError),
    #[error("{0}")]
    Sftp(#[from] SftpError),
    #[error("{0}")]
    Ssh(#[from] SshError),
    #[error("{0}")]
    Io(#[from] IOError),
    #[error("{0}")]
    Utf8(#[from] Utf8Error),
    #[error("{0}")]
    BorrowMut(#[from] BorrowMutError),
}

type HandlerResult<T> = Result<T, HandlerError>;
type HandlerValue<'a> = Result<Value<'a>, HandlerError>;

trait Handle<T> {
    fn handle(self) -> Result<T, HandlerError>;
}

impl<T, E: Into<HandlerError>> Handle<T> for Result<T, E> {
    fn handle(self) -> Result<T, HandlerError> {
        self.map_err(|e| e.into())
    }
}

fn with_channel<'a>(
    env: &'a Env,
    handler: impl Fn(&DissectedFilename, &Session, Channel) -> HandlerValue<'a>,
) -> EmacsResult<Value<'a>> {
    let dissected = env.default_directory()?;
    for retry in 0..RETRIES {
        let result: HandlerResult<(Rc<Session>, Channel)> = (|| {
            let session = get_connection(&dissected.user, &dissected.host, &env)?;
            let channel = session.new_channel()?;
            Ok((session, channel))
        })();
        match result {
            Ok((session, channel)) => return Ok(handler(&dissected, &*session, channel)?),
            Err(e) => {
                if retry == RETRIES
                    || !env.y_or_n_p(&format!(
                        "ssh error [{}] would you like to reconnect? ",
                        e.to_string()
                    ))?
                {
                    return Err(e.into());
                }
            }
        }
    }

    bail!("Should not get here");
}

fn with_sftp<'a>(
    env: &'a Env,
    tramp_path: Value<'a>,
    handler: impl Fn(&DissectedFilename, &Session, &Sftp) -> HandlerValue<'a>,
) -> EmacsResult<Value<'a>> {
    let mut error: Option<EmacsError> = None;
    for _retry in 0..RETRIES {
        let dissected = env.tramp_dissect_file_name(tramp_path)?;
        let session = get_connection(&dissected.user, &dissected.host, &env)?;
        let sftp = get_sftp(&dissected.user, &dissected.host, &*session)?;
        match handler(&dissected, &session, &sftp) {
            Ok(result) => return Ok(result),
            Err(HandlerError::Sftp(e)) => {
                if !env.y_or_n_p(&format!(
                    "ssh error [{}] would you like to reconnect? ",
                    e.to_string()
                ))? {
                    return Err(e.into());
                } else {
                    error = Some(e.into())
                }
            }
            Err(e) => return Err(e.into()),
        }
    }
    bail!(format!(
        "Too many retries, last error: {}",
        error.expect("Retried with no error").to_string()
    ))
}

#[defun]
fn write_region<'a>(
    env: &'a Env,
    start: Option<Value>,
    end: Option<Value>,
    filename: Value<'a>,
    append: Option<Value>,
    _visit: Option<Value>,
    _lockname: Option<Value>,
    _mustbenew: Option<Value>,
) -> EmacsResult<Value<'a>> {
    with_sftp(env, filename, |dissected, _session, sftp| {
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
            env.buffer_size()?.into()
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

        //let session = get_connection(&dissected.user, &dissected.host, &env)?;
        //let sftp_sess = session.sftp()?;
        let mut open_mode = OpenFlags::WRITE_ONLY | OpenFlags::CREATE;
        if append_file {
            open_mode |= OpenFlags::APPEND;
        } else if begin == 0 {
            open_mode |= OpenFlags::TRUNCATE;
        }
        let mut rfile = sftp.open(&dissected.filename, open_mode, 0o644)?;

        if !append_file {
            if let Some(seek) = seek {
                rfile.seek(SeekFrom::Start(seek)).handle()?;
            }
        }

        if let Some(str_contents) = str_contents {
            rfile.write(str_contents.as_bytes()).handle()?;
        } else {
            let mut cur_byte = begin + 1;

            loop {
                let substring_end = if end - cur_byte > BLOCKSIZE {
                    cur_byte + BLOCKSIZE
                } else {
                    end
                };

                let bufstring = env.buffer_substring_no_properties(cur_byte, substring_end)?;
                let written = rfile.write(bufstring.as_bytes()).handle()?;
                cur_byte += written;

                if cur_byte == end {
                    break;
                } else if cur_byte > end {
                    return Err(anyhow!("Wrote too much?").into());
                }
            }
        }

        Ok(t.bind(env))
    })
}

#[defun]
fn insert_file_contents<'a>(
    env: &'a Env,
    filename: Value<'a>,
    _visit: Option<Value>,
    begin: Option<usize>,
    end: Option<usize>,
    replace: Option<Value>,
) -> EmacsResult<Value<'a>> {
    with_sftp(env, filename, |dissected, _session, sftp| {
        let mut rfile = sftp.open(&dissected.filename, OpenFlags::READ_ONLY, 0)?;
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

        Ok(env.nil())
    })
}

#[defun]
fn file_exists_p<'a>(env: &'a Env, filename: Value<'a>) -> EmacsResult<Value<'a>> {
    with_sftp(env, filename, |dissected, _session, sftp| {
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
    })
}

#[defun]
fn directory_files<'a>(
    env: &'a Env,
    directory: Value<'a>,
    full_name: Option<Value<'a>>,
    match_regexp: Option<Value<'a>>,
    nosort: Option<Value<'a>>,
    count: Option<usize>,
) -> EmacsResult<Value<'a>> {
    directory_files_impl(
        env,
        directory,
        full_name,
        match_regexp,
        nosort,
        count,
        None,
        false,
    )
}

#[defun]
fn directory_files_and_attributes<'a>(
    env: &'a Env,
    directory: Value<'a>,
    full_name: Option<Value<'a>>,
    match_regexp: Option<Value<'a>>,
    nosort: Option<Value<'a>>,
    id_format: Option<Value<'a>>,
    count: Option<usize>,
) -> EmacsResult<Value<'a>> {
    directory_files_impl(
        env,
        directory,
        full_name,
        match_regexp,
        nosort,
        count,
        id_format,
        true,
    )
}

fn directory_files_impl<'a>(
    env: &'a Env,
    directory: Value<'a>,
    full_name: Option<Value<'a>>,
    match_regexp: Option<Value<'a>>,
    nosort: Option<Value<'a>>,
    count: Option<usize>,
    id_format: Option<Value<'a>>,
    with_attributes: bool,
) -> EmacsResult<Value<'a>> {
    with_sftp(env, directory, |dissected, _session, sftp| {
        let dir = sftp.open_dir(&dissected.filename)?;
        let mut dirlist: Value<'a> = nil.bind(env);
        let fs_metadata = sftp.vfs_metadata(&dissected.filename)?;

        let full_dir = if dissected.filename.ends_with("/") {
            dissected.filename.clone()
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
                    let lisp_name = name.into_lisp(env)?;
                    let entry = if with_attributes {
                        let lisp_attributes = metadata_to_file_attributes(
                            env,
                            &sftp,
                            *id_format.as_ref().unwrap(),
                            &full_dir,
                            &dissected,
                            &attributes,
                            &fs_metadata,
                        )?;
                        let mut entry = nil.bind(env);
                        entry = env.cons(lisp_attributes, entry)?;
                        entry = env.cons(lisp_name, entry)?;
                        entry
                    } else {
                        lisp_name
                    };
                    dirlist = env.cons(entry, dirlist)?;
                }
                None => break,
            }
        }

        if nosort.is_some() {
            Ok(dirlist)
        } else {
            Ok(env.nreverse(dirlist)?)
        }
    })
}

#[defun]
fn delete_file<'a>(env: &'a Env, filename: Value<'a>, _trash: Value<'a>) -> EmacsResult<Value<'a>> {
    with_sftp(env, filename, |dissected, _session, sftp| {
        sftp.remove_file(&dissected.filename)?;
        Ok(env.nil())
    })
}

fn metadata_to_file_attributes<'a>(
    env: &'a Env,
    sftp: &Sftp,
    id_format: Value<'a>,
    full_dir: &String,
    dissected: &DissectedFilename,
    metadata: &Metadata,
    fs_metadata: &VfsMetadata,
) -> EmacsResult<Value<'a>> {
    let mut hasher = DefaultHasher::new();
    dissected.user.hash(&mut hasher);
    dissected.host.hash(&mut hasher);
    let host_id = (hasher.finish() % i64::MAX as u64) as i64;
    let host_id = host_id.into_lisp(env)?;
    let vfs_id = ((fs_metadata.filesystem_id() % i64::MAX as u64) as i64).into_lisp(env)?;
    let fs_id = env.cons(host_id, vfs_id)?;

    hasher = DefaultHasher::new();
    let full_filename = format!(
        "{}{}",
        full_dir,
        metadata.name().context("Unable to get filename")?
    );
    full_filename.hash(&mut hasher);
    let file_num = (hasher.finish() % i64::MAX as u64) as i64;
    let file_num = file_num.into_lisp(env)?;

    let permissions = octal_permissions_to_string(
        metadata
            .permissions()
            .ok_or(anyhow!("Missing permissions"))?,
    )
    .into_lisp(env)?;

    let size = metadata.len().ok_or(anyhow!("Missing size"))?;

    // ctime isn't supported by the sftp protocol, fake it with mtime?
    let mtime = metadata
        .modified()
        .ok_or(anyhow!("Mising mtime"))?
        .into_lisp(env)?;
    let ctime = mtime;
    let atime = metadata.accessed().ok_or(anyhow!("Missing atime"))?;
    let atime = if atime == SystemTime::UNIX_EPOCH {
        mtime
    } else {
        atime.into_lisp(env)?
    };

    let (user, group) =
        if id_format.is_not_nil() && id_format.eq(string.bind(env)) {
            (
                // id format is string, try to get the username,
                // otherwise stringify the uid/gid
                match metadata.owner() {
                    Some(owner) => owner.into_lisp(env)?,
                    None => format!("{}", metadata.uid().ok_or(anyhow!("Missing UID"))?)
                        .into_lisp(env)?,
                },
                match metadata.group() {
                    Some(group) => group.into_lisp(env)?,
                    None => format!("{}", metadata.gid().ok_or(anyhow!("Missing GID"))?)
                        .into_lisp(env)?,
                },
            )
        } else if id_format.eq(integer.bind(env)) {
            (
                metadata
                    .uid()
                    .ok_or(anyhow!("MIssing UID"))?
                    .into_lisp(env)?,
                metadata
                    .gid()
                    .ok_or(anyhow!("Missing GID"))?
                    .into_lisp(env)?,
            )
        } else {
            bail!("Invalid id format");
        };

    let filetype = match metadata.file_type().ok_or(anyhow!("Missing file type"))? {
        FileType::Directory => t.bind(env),
        FileType::Symlink => sftp.read_link(&full_filename)?.into_lisp(env)?,
        _ => nil.bind(env),
    };

    nil.bind(env)
        .cons(fs_id)?
        .cons(file_num)?
        .cons(nil)?
        .cons(permissions)?
        .cons(size)?
        .cons(ctime)?
        .cons(mtime)?
        .cons(atime)?
        .cons(group)?
        .cons(user)?
        .cons(1)?
        .cons(filetype)
}

#[defun]
fn file_attributes<'a>(
    env: &'a Env,
    filename: Value<'a>,
    id_format: Value<'a>,
) -> EmacsResult<Value<'a>> {
    with_sftp(env, filename, |dissected, _session, sftp| {
        let path = Path::new(&dissected.filename);
        let dirname = path.parent().unwrap().to_str().unwrap().to_string();
        let dir = sftp.open_dir(&dirname)?;
        // For some reason you get more metadata from reading the directory than
        // you do just getting file attributes directly
        let metadata = {
            loop {
                match dir.read_dir().transpose()? {
                    Some(metadata) => match metadata.name() {
                        Some(filename) => {
                            if filename == path.file_name().unwrap() {
                                break metadata;
                            }
                        }
                        _ => continue,
                    },
                    None => Err(io::Error::from(io::ErrorKind::NotFound))?,
                }
            }
        };
        let fs_metadata = sftp.vfs_metadata(&dissected.filename)?;

        Ok(metadata_to_file_attributes(
            env,
            &sftp,
            id_format,
            &dirname,
            &dissected,
            &metadata,
            &fs_metadata,
        )?)
    })
}

#[defun]
fn process_file<'a>(
    env: &'a Env,
    program: Value<'a>,
    infile: Value<'a>,
    destination: Value<'a>,
    _display: Value<'a>,
    args: Value<'a>,
) -> EmacsResult<Value<'a>> {
    with_channel(env, |dissected, _session, channel| {
        let program = String::from_lisp(program)?;
        let arg_string = args
            .iter()
            .collect::<EmacsResult<Vec<Value<'a>>>>()?
            .iter()
            .map(|arg| String::from_lisp(*arg))
            .collect::<EmacsResult<Vec<String>>>()?
            .iter()
            .map(|arg| format!("'{}'", arg))
            .collect::<Vec<String>>()
            .join(" ");
        channel.open_session()?;
        let command = format!("cd {} && {} {}", &dissected.filename, &program, &arg_string);
        channel.request_exec(&command)?;
        let mut buf = [0; BLOCKSIZE];
        if infile.is_not_nil() {
            let infile = String::from_lisp(infile)?;
            let mut infile = File::open(&infile)?;
            let mut stdin = channel.stdin();
            loop {
                let bytes = infile.read(&mut buf)?;
                if bytes == 0 {
                    break;
                }

                stdin.write(&buf[0..bytes])?;
            }
        };

        channel.send_eof()?;

        if destination.is_not_nil() {
            let destination = env.get_buffer_create(destination)?;
            let orig_buf = env.current_buffer()?;
            env.set_buffer(destination)?;

            let mut maybe_stdout = Some(channel.stdout());
            let mut maybe_stderr = Some(channel.stderr());
            while maybe_stdout.is_some() || maybe_stderr.is_some() {
                if let Some(mut stderr) = maybe_stderr {
                    let bytes = stderr.read(&mut buf)?;
                    maybe_stderr = if bytes == 0 {
                        None
                    } else {
                        env.insert(&std::str::from_utf8(&buf[0..bytes])?)?;
                        Some(stderr)
                    };
                };
                if let Some(mut stdout) = maybe_stdout {
                    let bytes = stdout.read(&mut buf)?;
                    maybe_stdout = if bytes == 0 {
                        None
                    } else {
                        env.insert(&std::str::from_utf8(&buf[0..bytes])?)?;
                        Some(stdout)
                    }
                };
            }

            env.set_buffer(orig_buf)?;
        }

        channel
            .get_exit_status()
            .context("Unable to get exit status")?
            .into_lisp(env)
            .handle()
    })
}

fn octal_permissions_to_string(permissions: u32) -> String {
    let mut permissions: u32 = permissions;
    let mut ls: Vec<char> = "----------".chars().collect();

    let rmask = 4;
    let wmask = 2;
    let xmask = 1;

    let end = 9;
    for i in 0..3 {
        let set = end - i * 3;
        if permissions & xmask != 0 {
            ls[set] = 'x';
        }
        if permissions & wmask != 0 {
            ls[set - 1] = 'w';
        }
        if permissions & rmask != 0 {
            ls[set - 2] = 'r';
        }

        permissions = permissions >> 3;
    }

    ls.iter().collect()
}

#[defun]
fn bare<'a>(env: &'a Env, filename1: Value<'a>) -> EmacsResult<Value<'a>> {
    for _i in 0..10000 {
        let message = String::from_lisp(filename1)?;
        let message = message.into_lisp(env)?;
        env.call(get_t, &[message])?;
    }
    Ok(env.nil())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_octal_permissions_to_string() {
        assert_eq!(octal_permissions_to_string(0o755), "-rwxr-xr-x");
        assert_eq!(octal_permissions_to_string(0o644), "-rw-r--r--");
    }
}
