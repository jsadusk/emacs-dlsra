#include <emacs-module.h>
#include <emacs-module-helpers.h>
#include <libssh/libssh.h>
#include <stdlib.h>
#include <hashtable.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>

int plugin_is_GPL_compatible;

HashTable sessions_table;

void message(emacs_env *env, char* message) {
    emacs_value data = env->make_string (env, message,
                                         strlen (message));
    emacs_value message_str = env->make_string (env, message, strlen(message));
    env->funcall(env, env->intern(env, "message"), 1, &message_str);
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

ssh_session get_session(char* connection) {
    if (ht_contains(&sessions_table, connection)) {
        return (ssh_session)ht_lookup(&sessions_table, &connection);
    } else {
        ssh_session new_session;
        int rc;

        new_session = ssh_new();
        if (new_session == NULL)
            return NULL;

        int verbosity = SSH_LOG_PROTOCOL;
        int port = 22;

        ssh_options_set(new_session, SSH_OPTIONS_HOST, connection);
        ssh_options_set(new_session, SSH_OPTIONS_LOG_VERBOSITY, &verbosity);
        ssh_options_set(new_session, SSH_OPTIONS_PORT, &port);

        rc = ssh_connect(new_session);
        if (rc != SSH_OK) {
            fprintf(stderr, "Error connecting to localhost: %s\n",
                    ssh_get_error(new_session));
            return NULL;
        }

        if (verify_knownhost(*&new_session) != 0) {
            return NULL;
        }

        if (ssh_userauth_publickey_auto(new_session, NULL, NULL)) {
            return NULL;
        }
        
        ht_insert(&sessions_table, connection, new_session);

        return new_session;
    }
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

void sig_err(emacs_env *env, char* message) {
    emacs_value data = env->make_string (env, message,
                                         strlen (message));
    env->non_local_exit_signal
        (env, env->intern (env, "error"),
         env->funcall (env, env->intern (env, "list"), 1, &data));
}


static emacs_value dlsra_get_file_to_buffer (emacs_env *env, ptrdiff_t nargs, emacs_value args[], void *data) {
    emacs_value ret;
    if (nargs != 2) {
        sig_err(env, "Incorrect args");
        return ret;
    }

    ptrdiff_t full_path_size;
    env->copy_string_contents(env, args[0], NULL, &full_path_size);
    char* full_path = calloc(sizeof(char), full_path_size);
    env->copy_string_contents(env, args[0], full_path, &full_path_size);

    struct path_parts parts;
    if (get_path_parts(env, full_path, &parts) < 0) {
        sig_err(env, "Error in path parts");
        return ret;
    }

    ssh_session session = get_session(parts.host);
    if (session == NULL) {
        sig_err(env, "Error getting session");
        return ret;
    }

    return ret;
}

int emacs_module_init(struct emacs_runtime *ert)
{

  emacs_env *env = ert->get_environment(ert);
  ht_setup(&sessions_table, sizeof(char*), sizeof(ssh_session), 10);
  ht_reserve(&sessions_table, 100);

  DEFUN("dlsra-get-file-to-buffer-c", dlsra_get_file_to_buffer, 2, 2, "Get remote file to buffer", NULL);
  provide(env, "dlsra");
  
  return 0;
}
