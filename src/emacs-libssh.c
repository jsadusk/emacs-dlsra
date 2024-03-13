#include <emacs-module.h>
#include <emacs-module-helpers.h>
#include <libssh/libssh.h>
#include <libssh/sftp.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <sys/stat.h>
#include <fcntl.h>

int plugin_is_GPL_compatible;

emacs_value nilval(emacs_env *env) {
    return env->intern(env, "nil");
}

void message(emacs_env *env, const char* message) {
    emacs_value data = env->make_string (env, message,
                                         strlen (message));
    emacs_value message_str = env->make_string (env, message, strlen(message));
    env->funcall(env, env->intern(env, "message"), 1, &message_str);
}

void sig_err(emacs_env *env, const char* src, const char* message, const char *context) {
    char* full_message;
    if (context != NULL) {
        size_t len =  strlen(src) + strlen(message) + strlen(context) + 3;
        full_message = calloc(sizeof(char), len);
        snprintf("%s: %s: %s", len, message, context);
    } else {
        size_t len =  strlen(src) + strlen(message);
        full_message = calloc(sizeof(char), len);
        snprintf("%s: %s", len, message, context);
    }
    emacs_value data = env->make_string (env, message,
                                         strlen (message));
    env->non_local_exit_signal
        (env, env->intern (env, "error"),
         env->funcall (env, env->intern (env, "list"), 1, &data));
    free(full_message);
}

char* extract_str(emacs_env *env, emacs_value path_ev) {
    if (env->is_not_nil(env, path_ev)) {
        printf("string is not nil\n");
        ptrdiff_t size;
        env->copy_string_contents(env, path_ev, NULL, &size);
        char* strvalue = calloc(sizeof(char), size);
        env->copy_string_contents(env, path_ev, strvalue, &size);
        return strvalue;
    } else {
        printf("string is nil\n");
        sig_err(env, "extract_str", "string ev is nil", NULL);
        printf("signaled\n");
        return NULL;
    }
}

ssh_session extract_ssh_session(emacs_env* env, emacs_value session_ev) {
    ssh_session session = NULL;
    if (env->is_not_nil(env, session_ev)) {
        session = env->get_user_ptr(env, session_ev);
        if (session == NULL) {
            sig_err(env, "extract_ssh_session", "session ptr NULL", NULL);
        }
    } else {
        sig_err(env, "extract_ssh_session", "nil session ev", NULL);
    }

    return session;
}

sftp_session extract_sftp_session(emacs_env* env, emacs_value sftp_ev) {
    sftp_session sftp = NULL;
    if (env->is_not_nil(env, sftp_ev)) {
        sftp = env->get_user_ptr(env, sftp_ev);
        if (sftp == NULL) {
            sig_err(env, "extract_sftp_session", "sftp ptr", NULL);
        }
    } else {
        sig_err(env, "extract_sftp_session", "nil sftp ev", NULL);
    }

    return sftp;
}

/*static emacs_value emacs_libssh_scp_write (emacs_env *env, ptrdiff_t nargs, emacs_value args[], void *data) {
    emacs_value ret;
    int rc;
    if (nargs != 3) {
        sig_err(env, "Incorrect args");
        return ret;
    }

    emacs_value session_ev = args[0];
    emacs_value path_ev = args[1];
    emacs_value data_ev = args[2];

    ssh_session session;
    if (env->is_not_nil(env, session_ev)) {
        session = env->get_user_ptr(env, session_ev);
    } else {
        sig_err("nil session");
        return ret;
    }

    char *path = extract_str(env, path_ev);
    if (path == NULL) {
        sig_err("nil path");
        return ret;
    }

    char data = extract_str(env, data_ev);
    if (data == NULL) {
        sig_err("nil data");
        return ret;
    }

    ssh_scp scp = scp_new(session, SSH_SCP_WRITE, ".");
    if (scp == NULL) {
        sig_err("Error creating ssh");
        return ret;
    }
    }*/
const size_t MAX_XFER_BUF_SIZE = 16384;

static emacs_value emacs_libssh_sftp_insert (emacs_env *env, ptrdiff_t nargs, emacs_value argv[], void *data) {
    const char* src = "emacs_libssh_sftp_insert";
    fprintf(stderr, "in %s\n", src);
    
    emacs_value ret = nilval(env);
    if (nargs != 5) {
        sig_err(env, src, "Incorrect args", NULL);
        return ret;
    }

    ssh_session session = extract_ssh_session(env, argv[0]);
    if (!session)
        return ret;

    sftp_session sftp = extract_sftp_session(env, argv[1]);
    if (!session)
        return ret;

    char *filename = extract_str(env, argv[2]);
    if (!filename) {
        sig_err(env, src, "nil filename", NULL);
        return ret;
    }

    int begin = extract_integer(env, argv[3]);
    int end = extract_integer(env, argv[4]);

    sftp_file rfile = sftp_open(sftp, filename, O_RDONLY, 0);
    if (rfile == NULL) {
        sig_err(env, src, "Error opening remote file", ssh_get_error(session));
        return ret;
    }

    int nbytes = 0;
    char buffer[MAX_XFER_BUF_SIZE];
    fprintf(stderr, "interning\n");
    emacs_value insert_fun = env->intern(env, "insert");

    int readlen = INT_MAX;
    if (begin > 0) {

        if (sftp_seek64(rfile, begin) < 0) {
            sig_err(env, src, "Error seeking read", NULL);
            return ret;
        }

        if (end > 0) {
            readlen = end - begin;
        }
    }

    int total_bytes = 0;
    for (;;) {
        int remaining_bytes = readlen - total_bytes;
        int readsize = (remaining_bytes < MAX_XFER_BUF_SIZE ?
                        remaining_bytes : MAX_XFER_BUF_SIZE);
        fprintf(stderr, "reading\n");
        nbytes = sftp_read(rfile, buffer, readsize);
        if (nbytes == 0) {
            fprintf(stderr, "done reading\n");
            break; // EOF
        } else if (nbytes < 0) {
            fprintf(stderr, "read err\n");
            sig_err(env, src, "Error in sftp_read", ssh_get_error(session));
            sftp_close(rfile);
            return ret;
        }

        fprintf(stderr, "making string\n");
        emacs_value buffer_str = env->make_string(env, buffer, nbytes);
        fprintf(stderr, "inserting\n");
        env->funcall(env, insert_fun, 1, &buffer_str);
        fprintf(stderr, "done loop\n");
        total_bytes += nbytes;
        // TODO: non-local exit check

        if (total_bytes >= readlen) {
            fprintf(stderr, "Read to readlen\n");
            break;
        }
    }

    fprintf(stderr, "closing\n");
    sftp_close(rfile);
    fprintf(stderr, "closed\n");
    return ret;
}

static emacs_value emacs_libssh_sftp_write_region (emacs_env *env, ptrdiff_t nargs, emacs_value argv[], void *data) {
    const char* src = "emacs_libssh_sftp_write_region";
    fprintf(stderr, "in %s\n", src);

    emacs_value ret = nilval(env);
    if (nargs != 6) {
        sig_err(env, src, "Incorrect args", NULL);
        return ret;
    }

    ssh_session session = extract_ssh_session(env, argv[0]);
    if (!session)
        return ret;

    sftp_session sftp = extract_sftp_session(env, argv[1]);
    if (!session)
        return ret;

    char *filename = extract_str(env, argv[2]);
    if (!filename) {
        sig_err(env, src, "nil filename", NULL);
        return ret;
    }

    int begin = extract_integer(env, argv[3]);
    int end = extract_integer(env, argv[4]);
    int seek = extract_integer(env, argv[5]);


    fprintf(stderr, "open\n");
    sftp_file rfile = sftp_open(sftp, filename, O_WRONLY|O_CREAT|O_TRUNC, 0666);
    if (rfile == NULL) {
        sig_err(env, src, "Error opening remote file", ssh_get_error(session));
        return ret;
    }

    int nbytes = 0;
    char buffer[MAX_XFER_BUF_SIZE];

    fprintf(stderr, "seek\n");
    int writelen = INT_MAX;
    if (seek > 0) {
        if (sftp_seek64(rfile, seek) < 0) {
            sig_err(env, src, "Error seeking write", ssh_get_error(session));
            return ret;
        }
    }

    int cur_byte = begin;
    fprintf(stderr, "intern\n");
    emacs_value buffer_substring_no_properties = env->intern(env, "buffer-substring-no-properties");
    for (;;) {
        int remaining = end - cur_byte;
        int writesize = remaining < MAX_XFER_BUF_SIZE ? remaining : MAX_XFER_BUF_SIZE;

        fprintf(stderr, "makeint\n");
        emacs_value args[2] = {env->make_integer(env, cur_byte), env->make_integer(env, cur_byte + writesize)};
        fprintf(stderr, "substring\n");
        emacs_value substring_ev = env->funcall(env, buffer_substring_no_properties, 2, args);
        fprintf(stderr, "extract substr\n");
        char *substring = extract_str(env, substring_ev);
        if (substring == NULL) {
            printf("null substring\n");
            return ret;
        }

        fprintf(stderr, "write %d bytes\n", writesize);
        int written = sftp_write(rfile, substring, writesize);
        if (written < 0) {
            sig_err(env, src, "Error writing to sftp", ssh_get_error(session));
            return ret;
        }
        

        cur_byte += written;
        if (cur_byte >= end) {
            break;
        }
    }
    
    return ret;
}

int verify_knownhost(ssh_session session)
{
    enum ssh_known_hosts_e state;
    unsigned char *hash = NULL;
    ssh_key srv_pubkey = NULL;
    size_t hlen;
    char buf[10];
    char *hexa;
    char *p;
    int cmp;
    int rc;
 
    rc = ssh_get_server_publickey(session, &srv_pubkey);
    if (rc < 0) {
        return -1;
    }
 
    rc = ssh_get_publickey_hash(srv_pubkey,
                                SSH_PUBLICKEY_HASH_SHA1,
                                &hash,
                                &hlen);
    ssh_key_free(srv_pubkey);
    if (rc < 0) {
        return -1;
    }
 
    state = ssh_session_is_known_server(session);
    switch (state) {
        case SSH_KNOWN_HOSTS_OK:
            /* OK */
 
            break;
        case SSH_KNOWN_HOSTS_CHANGED:
            fprintf(stderr,  "Host key for server changed: it is now:\n");
            fprintf(stderr,  "Public key hash");
            ssh_print_hash(SSH_PUBLICKEY_HASH_SHA256, hash, hlen);
            fprintf(stderr,  "For security reasons, connection will be stopped\n");
            ssh_clean_pubkey_hash(&hash);
 
            return -1;
        case SSH_KNOWN_HOSTS_OTHER:
            fprintf(stderr,  "The host key for this server was not found but an other"
                    "type of key exists.\n");
            fprintf(stderr,  "An attacker might change the default server key to"
                    "confuse your client into thinking the key does not exist\n");
            ssh_clean_pubkey_hash(&hash);
 
            return -1;
        case SSH_KNOWN_HOSTS_NOT_FOUND:
            fprintf(stderr,  "Could not find known host file.\n");
            fprintf(stderr, "If you accept the host key here, the file will be"
                    "automatically created.\n");
 
            /* FALL THROUGH to SSH_SERVER_NOT_KNOWN behavior */
 
        case SSH_KNOWN_HOSTS_UNKNOWN:
            hexa = ssh_get_hexa(hash, hlen);
            fprintf(stderr,"The server is unknown. Do you trust the host key?\n");
            fprintf(stderr, "Public key hash: %s\n", hexa);
            ssh_string_free_char(hexa);
            ssh_clean_pubkey_hash(&hash);
            p = fgets(buf, sizeof(buf), stdin);
            if (p == NULL) {
                return -1;
            }
 
            cmp = strncasecmp(buf, "yes", 3);
            if (cmp != 0) {
                return -1;
            }
 
            rc = ssh_session_update_known_hosts(session);
            if (rc < 0) {
                fprintf(stderr, "Error %s\n", strerror(errno));
                return -1;
            }
 
            break;
        case SSH_KNOWN_HOSTS_ERROR:
            fprintf(stderr, "Error %s", ssh_get_error(session));
            ssh_clean_pubkey_hash(&hash);
            return -1;
    }
 
    ssh_clean_pubkey_hash(&hash);
    return 0;
}

ssh_session get_session(emacs_env *env, char* username, char* hostname) {

    char *connection = NULL;
    if (username == NULL) {
        connection = hostname;
    } else {
        uint usersize = strlen(username);
        uint hostsize = strlen(hostname);
        connection = calloc(sizeof(char), usersize + hostsize + 2);
        snprintf(connection, usersize + hostsize + 2, "%s@%s", username, hostname);
    }

    ssh_session session = NULL;
    {
        const char* fmt = "Connecting ssh session for: %s";
        char* message_str = calloc(sizeof(char), strlen(connection) + strlen(fmt));
        sprintf(message_str, fmt, connection);
        message(env, message_str);
        free(message_str);
    }
    int rc;

    session = ssh_new();
    if (session == NULL)
        return NULL;

    int verbosity = SSH_LOG_PROTOCOL;
    int port = 22;

    ssh_options_set(session, SSH_OPTIONS_HOST, hostname);
    ssh_options_set(session, SSH_OPTIONS_LOG_VERBOSITY, &verbosity);
    ssh_options_set(session, SSH_OPTIONS_PORT, &port);

    if (username != NULL) {
        ssh_options_set(session, SSH_OPTIONS_USER, username);
    }

    ssh_options_parse_config(session, NULL);

    rc = ssh_connect(session);
    if (rc != SSH_OK || session == NULL) {
        {
            const char* fmt = "Error connecting ssh: %s";
            char* message_str = calloc(sizeof(char), strlen(connection) + strlen(fmt));
            sprintf(message_str, fmt, connection);
            message(env, message_str);
            free(message_str);
        }
            
        return NULL;
    }

    {
        const char* fmt = "Connected, verifying knownhost: %s";
        char *message_str = calloc(sizeof(char), strlen(connection) + strlen(fmt));
        sprintf(message_str, fmt, connection);
        message(env, message_str);
        free(message_str);
    }

    if (verify_knownhost(session) != 0) {
        return NULL;
    }

    {
        const char* fmt = "Connected, authenticating: %s";
        char *message_str = calloc(sizeof(char), strlen(connection) + strlen(fmt));
        sprintf(message_str, fmt, connection);
        message(env, message_str);
        free(message_str);
    }

    if (ssh_userauth_publickey_auto(session, NULL, NULL)) {
        return NULL;
    }
        
    {
        const char* fmt = "Session established: %s";
        char *message_str = calloc(sizeof(char), strlen(connection) + strlen(fmt));
        sprintf(message_str, fmt, connection);
        message(env, message_str);
        free(message_str);
    }

    if (username != NULL) {
        free(connection);
    }
    return session;
}

struct path_parts {
    char *user;
    char *host;
    char *filename;
};

int get_path_parts(emacs_env *env, char* path_str, struct path_parts* parts) {
    const char* connection_prefix = "/dlsra";
    message(env, "in get_path_parts");
    unsigned int i = 0;
    while (path_str[i] != ':' && path_str[i] != '\0') {
        if (path_str[i] != connection_prefix[i]) {
            message(env, "get_path_parts: mismatched prefix");
            return -1;
        }
        ++i;
    }

    if (path_str[i] == '\0') {
        message(env, "get_path_parts: error finding first colon");
        return -1;
    }

    char* begin = path_str + i + 1;
    char* end = begin;
    while (*end != ':' && *end != '\0') {
        ++end;
    }

    if (*end == '\0' || begin == end) {
        message(env, "get_path_parts: error finding second colon");
        return -1;
    }
    
    parts->user = NULL;
    unsigned hostlen = end - begin;
    parts->host = calloc(sizeof(char), hostlen + 1);
    strncpy(parts->host, begin, hostlen);
    char* filename = end + 1;
    unsigned filename_len = strlen(filename);
    parts->filename = calloc(sizeof(char), filename_len + 1);
    strncpy(parts->filename, filename, filename_len);

    return 0;
}

void ssh_session_finalizer(void *ptr) {
    fprintf(stderr, "session finalizer\n");
    ssh_session session = (ssh_session)ptr;
    ssh_free(session);
    fprintf(stderr, "session finalizer done\n");
}

void sftp_session_finalizer(void *ptr) {
    fprintf(stderr, "sftp finalizer\n");
    sftp_session sftp = (sftp_session)ptr;
    sftp_free(sftp);
    fprintf(stderr, "sftp finalizer done\n");
}

static emacs_value emacs_libssh_get_ssh_session (emacs_env *env, ptrdiff_t nargs, emacs_value args[], void *data) {
    const char* src = "emacs_libssh_get_session";
    fprintf(stderr, "in %s\n", src);
    emacs_value ret = nilval(env);
    if (nargs != 2) {
        sig_err(env, src, "Incorrect args", NULL);
        return ret;
    }

    char* username = NULL;
    if (env->is_not_nil(env, args[0])) {
        ptrdiff_t usersize;
        env->copy_string_contents(env, args[0], NULL, &usersize);
        username = calloc(sizeof(char), usersize);
        env->copy_string_contents(env, args[0], username, &usersize);
    }

    char* hostname = NULL;
    if (env->is_not_nil(env, args[1])) {
        ptrdiff_t hostsize;
        env->copy_string_contents(env, args[1], NULL, &hostsize);
        hostname = calloc(sizeof(char), hostsize);
        env->copy_string_contents(env, args[1], hostname, &hostsize);
    } else {
        sig_err(env, src, "hostname nil", NULL);
        return ret;
    }
    
    ssh_session session = get_session(env, username, hostname);
    if (session == NULL) {
        sig_err(env, src, "Error getting session", NULL);
        return ret;
    }

    ret = env->make_user_ptr(env, ssh_session_finalizer, session);
    return ret;
}

static emacs_value emacs_libssh_get_sftp_session (emacs_env *env, ptrdiff_t nargs, emacs_value args[], void *data) {
    const char* src = "emacs_libssh_get_sftp";
    fprintf(stderr, "in %s\n", src);
    emacs_value ret = nilval(env);
    if (nargs != 1) {
        sig_err(env, src, "Incorrect args", NULL);
        return ret;
    }

    ssh_session session = extract_ssh_session(env, args[0]);

    sftp_session sftp = sftp_new(session);
    if (sftp == NULL) {
        sig_err(env, src, "Error allocating sftp", NULL);
        return ret;
    }

    if (sftp_init(sftp) != SSH_OK) {
        sig_err(env, src, "Error initializing sftp", NULL);
        sftp_free(sftp);
        return ret;
    }

    ret = env->make_user_ptr(env, sftp_session_finalizer, sftp);

    return ret;
}

static emacs_value emacs_libssh_marker (emacs_env *env, ptrdiff_t nargs, emacs_value args[], void *data) {
    fprintf(stderr, "marker");
    return 0;
}

int emacs_module_init(struct emacs_runtime *ert)
{

  emacs_env *env = ert->get_environment(ert);

  DEFUN("emacs-libssh-sftp-write-region", emacs_libssh_sftp_write_region, 6, 6, "Write a region from the current buffer into an sftp file", NULL);
  DEFUN("emacs-libssh-get-ssh-session", emacs_libssh_get_ssh_session, 2, 2, "Get an ssh session", NULL);
  DEFUN("emacs-libssh-get-sftp-session", emacs_libssh_get_sftp_session, 1, 1, "Get an sftp session", NULL);
  DEFUN("emacs-libssh-sftp-insert", emacs_libssh_sftp_insert, 5, 5, "Insert a file from sftp into the current buffer", NULL);
  provide(env, "emacs-libssh");
  
  return 0;
}
