#include <emacs-module.h>
#include <emacs-module-helpers.h>
#include <libssh/libssh.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>

int plugin_is_GPL_compatible;

void message(emacs_env *env, char* message) {
    emacs_value data = env->make_string (env, message,
                                         strlen (message));
    emacs_value message_str = env->make_string (env, message, strlen(message));
    env->funcall(env, env->intern(env, "message"), 1, &message_str);
}

void sig_err(emacs_env *env, char* message) {
    emacs_value data = env->make_string (env, message,
                                         strlen (message));
    env->non_local_exit_signal
        (env, env->intern (env, "error"),
         env->funcall (env, env->intern (env, "list"), 1, &data));
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
            fprintf(stderr, "Host key for server changed: it is now:\n");
            fprintf(stderr, "Public key hash");
            ssh_print_hash(SSH_PUBLICKEY_HASH_SHA256, hash, hlen);
            fprintf(stderr, "For security reasons, connection will be stopped\n");
            ssh_clean_pubkey_hash(&hash);
 
            return -1;
        case SSH_KNOWN_HOSTS_OTHER:
            fprintf(stderr, "The host key for this server was not found but an other"
                    "type of key exists.\n");
            fprintf(stderr, "An attacker might change the default server key to"
                    "confuse your client into thinking the key does not exist\n");
            ssh_clean_pubkey_hash(&hash);
 
            return -1;
        case SSH_KNOWN_HOSTS_NOT_FOUND:
            fprintf(stderr, "Could not find known host file.\n");
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
    ssh_session session = (ssh_session)ptr;
    ssh_free(session);
}

static emacs_value emacs_libssh_get_session (emacs_env *env, ptrdiff_t nargs, emacs_value args[], void *data) {
    emacs_value ret;
    if (nargs != 2) {
        sig_err(env, "Incorrect args");
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
        sig_err(env, "hostname nil");
        return ret;
    }
    
    ssh_session session = get_session(env, username, hostname);
    if (session == NULL) {
        sig_err(env, "Error getting session");
        return ret;
    }

    ret = env->make_user_ptr(env, ssh_session_finalizer, session);
    return ret;
}

int emacs_module_init(struct emacs_runtime *ert)
{

  emacs_env *env = ert->get_environment(ert);

  DEFUN("emacs-libssh-get-session", emacs_libssh_get_session, 2, 2, "Get an ssh session", NULL);
  provide(env, "emacs-libssh");
  
  return 0;
}
