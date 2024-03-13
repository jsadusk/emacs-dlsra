use std::cell::RefCell;
use emacs::{defun, CallEnv, Env, IntoLisp, Result, Value, FromLisp};

emacs::plugin_is_GPL_compatible!();

use libssh_rs::*;

/*thread_local! {
    static SESSIONS: RefCell<HashMap<String, Session>>;
}*/

#[emacs::module(name = "tramp-libssh")]
fn init(_: &Env) -> Result<()> { Ok(()) }

struct LocalEnv<'a> {
    pub env: &'a Env,
    nil_v: Value<'a>,
    car_v: Value<'a>,
    cdr_v: Value<'a>,
    nth_v: Value<'a>,
    tramp_dissect_file_name_v: Value<'a>,
}

impl<'a> LocalEnv<'a> {
    pub fn new(env: &'a Env) -> Result<Self> {
        Ok(Self {
            env: env,
            nil_v: env.intern("nil")?,
            car_v: env.intern("car")?,
            cdr_v: env.intern("cdr")?,
            nth_v: env.intern("nth")?,
            tramp_dissect_file_name_v: env.intern("tramp-dissect-file-name")?,
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
    
    pub fn nth(&self, idx: i64, list: Value<'a>) -> Result<Value<'a>> {
        self.env.call(self.nth_v, &[idx.into_lisp(self.env)?, list])
    }

    pub fn tramp_dissect_file_name(&self, filename: Value<'a>) -> Result<Value<'a>> {
        self.env.call(self.tramp_dissect_file_name_v, &[filename])
    }

    pub fn message(&self, msg: &str) -> Result<Value<'a>> {
        self.env.message(msg)
    }

    pub fn intern(&self, symbol: &str) -> Result<Value<'a>> {
        self.env.intern(symbol)
    }

}

#[defun]
fn insert_file_contents1(env: &Env, filename: Value, visit: Option<Value>, begin: Option<i64>, end: Option<i64>, replace: Option<Value>) -> Result<()> {
    let env = LocalEnv::new(env)?;
    env.message("insert-file-contents")?;
    let dissected = env.tramp_dissect_file_name(filename)?;
    let username = env.nth(2, dissected)?;
    let host = env.nth(4, dissected)?;
    
    env.message(&format!("filename {} has username {} host {}", String::from_lisp(filename)?, String::from_lisp(username)?, String::from_lisp(host)?))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
    }
}
