///
/// help function
///

#include "tunc_help.h"
#include "config.h"

static const char cust_str[] = "sign_algo=sha2";

static SSL_CTX *create_ssl_ctx(const char *sign_algo, ssl_conn_t *ssl_con);
static int add_cust_ext_callback(SSL *s, unsigned int ext_type,
        const unsigned char **out, size_t *outlen, int *al, void *arg);
static int client_open_socket(std::string &host, int port);

std::map<int, bool> connections;
conf_map_t conf_map;

int exact_write(int fd, void *buffer, int length)
{
    int    bytes_left, written_bytes;
    char  *ptr = static_cast<char*>(buffer);

    bytes_left = length;

    while (bytes_left > 0) {
        written_bytes = send(fd, ptr, bytes_left,0);
        if (written_bytes <= 0) {
            if(errno == EINTR || errno == EAGAIN) {
                written_bytes = 0;
			} else {
                // todo fatal error
                return -1;
            }
        }
        bytes_left -= written_bytes;
        ptr += written_bytes;
    }
    return 0;
}

int ssl_exact_read(SSL *ssl, void *buffer, int length)
{
    int    bytes_left, bytes_read;
    char  *ptr = static_cast<char*>(buffer);

    bytes_left = length;

    while (bytes_left > 0) {
        bytes_read = SSL_read(ssl, ptr, bytes_left);
        if (bytes_read <= 0) {
            int err = SSL_get_error(ssl,bytes_read);
            if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
                bytes_read = 0;
            } else {
                // todo fatal error
                return -1;
            }
        }
        bytes_left -= bytes_read;
        ptr += bytes_read;
    }
    return 0;
}

int ssl_exact_write(SSL *ssl, void *buffer, int length)
{
    int    bytes_left, written_bytes;
    char  *ptr = static_cast<char*>(buffer);

    bytes_left = length;

    while (bytes_left > 0) {
        written_bytes = SSL_write(ssl, ptr, bytes_left);
        if (written_bytes <= 0) {
            int err = SSL_get_error(ssl,written_bytes);
            if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
                written_bytes = 0;
            } else {
                // todo fatal error
                return -1;
            }
        }
        bytes_left -= written_bytes;
        ptr += written_bytes;
    }

    return 0;
}

int handle_accept(int fd, fd_port_map_t &port_map)
{
    int client = accept(fd, nullptr, 0);
    if (client > 0) {
        port_map[client] = port_map[fd];
    }
    return client;
}

int handle_ssl_read(ssl_conn_t *ssl_con)
{
    char buf[PROTO_HEAD_SIZE + USER_MSG_SIZE] = {0};

    int n = ssl_exact_read(ssl_con->ssl, buf, PROTO_HEAD_SIZE);
    if (n != 0) {
        ssl_con->connected = false;
        //cleanup_ssl(ssl_con);
        //client_open_ssl(ssl_con);
		return -1;
    }

    uint32_t len,nlen;
    memcpy(&nlen, buf, 4);
    len = ntohl(nlen);

    uint32_t port, nport;
    memcpy(&nport, buf + 4, 4);
    port = ntohl(nport);

    uint32_t fd, nfd;
    memcpy(&nfd, buf + 8, 4);
    fd = ntohl(nfd);

    std::cout << "ssl data size <--- " << len << "\n";

    n = ssl_exact_read(ssl_con->ssl, buf + PROTO_HEAD_SIZE, len);
    if (n != 0) {
        ssl_con->connected = false;
        //cleanup_ssl(ssl_con);
        //client_open_ssl(ssl_con);
        return -1;
    }

    n = exact_write(fd, buf + PROTO_HEAD_SIZE, len);
	if (n == -1) {
		connections[fd] = false;
		close(fd);
	}

    return 0;
}

int handle_read_client(int fd, ssl_conn_t *ssl_con,
                       fd_port_map_t &port_map)
{
    char buf[PROTO_HEAD_SIZE + USER_MSG_SIZE] = {0};

    int n = recv(fd, buf + PROTO_HEAD_SIZE, USER_MSG_SIZE,0);
    if (n <= 0) {
		if (errno != EINTR && errno != EAGAIN) {
			//std::cout << "recv 111\n";
			//connections[fd] = false;
			//close(fd);
		}
		return -1;
    }

    std::cout << "client data size ---> " << n << "\n\n";

#if (0)
    char *p = buf + PROTO_HEAD_SIZE;
    for (int i = 0; i < n; ++i) {
        printf("%02x", p[i]);
    }
    printf("\n");
#endif

    uint32_t len = n, nlen;
    nlen = htonl(len);
    memcpy(buf, &nlen, 4);

    uint32_t port = port_map[fd], nport;
    nport = htonl(port);
    memcpy(buf + 4, &nport, 4);

    uint32_t nfd;
    nfd = htonl(fd);
    memcpy(buf + 8, &nfd, 4);

    int ret = ssl_exact_write(ssl_con->ssl, buf, n + PROTO_HEAD_SIZE);
    if (ret != 0) {
        std::cout << "client write to ssl fail\n";
		ssl_con->connected = false;
        //cleanup_ssl(ssl_con);
        //client_open_ssl(ssl_con);
		return -1;
        //return ssl_exact_write(ssl_con->ssl, buf, n + PROTO_HEAD_SIZE);
    }

    return 0;
}

void init_openssl()
{
    SSL_library_init();
    SSL_load_error_strings();

    OpenSSL_add_all_algorithms();
}

void cleanup_ssl(ssl_conn_t *ssl_conn)
{
    SSL_shutdown(ssl_conn->ssl);
    SSL_CTX_free(ssl_conn->ssl_ctx);
	SSL_free(ssl_conn->ssl);

    close(ssl_conn->fd);
}

int init_ssl_config(ssl_conn_t *ssl_config)
{
    ssl_config->verify_peer = true;
    conf_map_t::iterator it;
    it = conf_map.find("ssl");
    if (it != conf_map.end()) {
        ssl_config->ssl_host = it->second.second;
        ssl_config->ssl_port = it->second.first;
    } else {
        std::cout << "no ssl configuration\n";
    }

	return 0;
}

int server_open_socket(int port, fd_port_map_t &port_map)
{
    int fd;
    struct sockaddr_in addr;

    memset(&addr, 0, sizeof(struct sockaddr_in));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("socket() failed");
        exit(EXIT_FAILURE);
    }

    int on = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (char*) &on, sizeof(int));

    if (bind(fd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
        perror("bind() failed");
        exit(EXIT_FAILURE);
    }

    if (listen(fd, 5) < 0) {
        perror("listen() failed");
        exit(EXIT_FAILURE);
    }

    port_map[fd] = port;

    return fd;
}

static void *fill_in_addr(struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET) {
        return &(((struct sockaddr_in*)sa)->sin_addr);
    }

    return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

static int connect_by_hostname(std::string& host,int port)
{
    int   fd,rv;
    struct addrinfo hints, *servinfo, *p;
    char  s[INET6_ADDRSTRLEN];

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;// AF_UNSPEC AF_INET6
    hints.ai_socktype = SOCK_STREAM;

    char service[128] = {0};
    sprintf(service,"%d",port);

    if ((rv = getaddrinfo(host.c_str(), service, &hints, &servinfo)) != 0) {
        fprintf(stderr, "client getaddrinfo: %s\n", gai_strerror(rv));
        return -1;
    }

    for (p = servinfo; p != nullptr; p = p->ai_next) {
        if ((fd = socket(p->ai_family, p->ai_socktype,p->ai_protocol)) == -1) {
            perror("ssl client socket");
            continue;
        }

        if (connect(fd, p->ai_addr, p->ai_addrlen) == -1) {
            perror("ssl connect");
            close(fd);
            continue;
        }

        break;
    }

    if (p == nullptr) {
        fprintf(stderr, "fail to connect to ssl server\n");
        return -1;
    }

    inet_ntop(p->ai_family, fill_in_addr((struct sockaddr *)p->ai_addr),s, sizeof s);
    std::cout << "connection to ssl server: " << s << "\n";

    freeaddrinfo(servinfo);

    return fd;
}

static int client_open_socket(std::string &host, int port)
{
    return connect_by_hostname(host,port);
}

static int add_cust_ext_callback(SSL *s, unsigned int ext_type,
                                 const unsigned char **out,
                                 size_t *outlen, int *al, void *arg)
{
    printf("-----add cust ext-----\n");

    *out = (const unsigned char *) cust_str;
    *outlen = strlen(cust_str);

    return 1;
}

int client_open_ssl(ssl_conn_t *ssl_con)
{
    init_openssl();

    ssl_con->fd = client_open_socket(ssl_con->ssl_host, ssl_con->ssl_port);
    ssl_con->ssl_ctx = create_ssl_ctx("sha2", ssl_con);

    ssl_con->ssl = SSL_new(ssl_con->ssl_ctx);
    if (!ssl_con->ssl) {
        printf("SSL_new() failed\n");
        return -1;
    }
    SSL_set_fd(ssl_con->ssl, ssl_con->fd);

    //std::cout << "SSL_connect-->\n";
    int ret;
    if ((ret = SSL_connect(ssl_con->ssl)) != 1) {
        ERR_print_errors_fp(stderr);
        printf("SSL_connect ERR: %d\n", SSL_get_error(ssl_con->ssl, ret));
        return -1;
    }

    //std::cout << "SSL_connect 1\n";

    std::cout << "verify_peer\n";

    if (ssl_con->verify_peer) {
        X509 *cert = SSL_get_peer_certificate(ssl_con->ssl);
        if (cert) {
            long ret = SSL_get_verify_result(ssl_con->ssl);
            if (ret != X509_V_OK) {
                printf("verify failed\n");
                goto fail;
            } else {
                printf("verify ok\n");
            }
            X509_free(cert);
        } else {
            printf("no peer certificate\n");
        }
    }

    return ssl_con->fd;

fail:

    SSL_shutdown(ssl_con->ssl);
    SSL_free(ssl_con->ssl);
    SSL_CTX_free(ssl_con->ssl_ctx);
    close(ssl_con->fd);

    return -1;
}

static SSL_CTX *create_ssl_ctx(const char *sign_algo,
                               ssl_conn_t *ssl_con)
{
    ssl_con->ssl_ctx = SSL_CTX_new(SSLv23_client_method());
    if (!ssl_con->ssl_ctx) {
        ERR_print_errors_fp(stderr);
        return nullptr;
    }

    SSL_CTX_add_client_custom_ext(ssl_con->ssl_ctx, CUSTOM_EXT_TYPE_1000,
                                  add_cust_ext_callback,
                                  nullptr, nullptr,
                                  nullptr, nullptr);

    char file_name[512] = {0};
    sprintf(file_name, "client_%s.crt", sign_algo);

#if (0)
#if (1)
    //SSL_CTX_use_certificate_file SSL_FILETYPE_PEM
    if (SSL_CTX_use_certificate_file(ssl_con->ssl_ctx, file_name,
                                     SSL_FILETYPE_PEM) <= 0) {
        //printf("SSL_CTX_use_certificate_file() fail");
        ERR_print_errors_fp(stderr);
        return nullptr;
    }
#else
    X509 *x509 = load_cert(file_name);

    if (SSL_CTX_use_certificate(ssl_ctx, x509) <= 0) {
        //printf("SSL_CTX_use_certificate_file() fail");
        ERR_print_errors_fp(stderr);
        return nullptr;
    }
    X509_free(x509);
#endif

    sprintf(file_name, "client_%s.key", sign_algo);
    if (SSL_CTX_use_PrivateKey_file(ssl_con->ssl_ctx, file_name,
                                    SSL_FILETYPE_PEM) <= 0) {
        //printf("SSL_CTX_use_PrivateKey_file() fail");
        ERR_print_errors_fp(stderr);
        return nullptr;
    }

    if (SSL_CTX_check_private_key(ssl_con->ssl_ctx) != 1) {
        //printf("Private and certificate is not matching\n");
        ERR_print_errors_fp(stderr);
        return nullptr;
    }
#endif

    // we can string certs together to form a cert-chain
    sprintf(file_name, "ca_%s.crt", sign_algo);
    if (!SSL_CTX_load_verify_locations(ssl_con->ssl_ctx, file_name, nullptr)) {
        ERR_print_errors_fp(stderr);
        return nullptr;
    }
    SSL_CTX_set_verify(ssl_con->ssl_ctx, SSL_VERIFY_PEER, nullptr);
    //SSL_CTX_set_verify_depth(ssl_ctx, 1);
    //SSL_CTX_set_tlsext_servername_callback(ssl_ctx, svr_name_callback);

    return ssl_con->ssl_ctx;
}
