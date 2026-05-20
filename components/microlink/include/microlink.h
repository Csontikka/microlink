/**
 * @file microlink.h
 * @brief MicroLink v2 - ESP32 Tailscale Client (Public API)
 *
 * Production-ready Tailscale client for ESP32-S3 with:
 * - Queue-based architecture (no mutex deadlocks)
 * - Dedicated tasks for DERP TX, network I/O, coordination, WireGuard
 * - Rate-limited DISCO (matching native tailscaled timing)
 * - Async STUN (non-blocking)
 * - PSRAM-optimized memory layout
 */

#pragma once

#include "esp_err.h"
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Opaque handle */
typedef struct microlink_s microlink_t;

/* Configuration */
typedef struct {
    const char *auth_key;       /* Tailscale auth key (tskey-auth-...) */
    const char *device_name;    /* Device hostname on the tailnet */
    bool enable_derp;           /* Enable DERP relay (default: true) */
    bool enable_stun;           /* Enable STUN endpoint discovery */
    bool enable_disco;          /* Enable DISCO NAT traversal */
    uint8_t max_peers;          /* Max simultaneous peers (default: 16) */
    int8_t wifi_tx_power_dbm;   /* WiFi TX power in dBm (0 = default 19.5) */

    /* Priority peer: guaranteed a WG slot even when peer table is full.
     * On large tailnets the NVS cache can fill the peer table at boot
     * before the priority peer arrives from MapResponse. When the table
     * is full and a peer matching this IP arrives, the least-recently-used
     * non-priority peer is evicted to make room.
     * Set to 0 to disable (all peers treated equally). */
    uint32_t priority_peer_ip;  /* VPN IP in host byte order (e.g., microlink_parse_ip("100.x.y.z")) */

    /* Exit node peer: when set, the matching peer is added with 0.0.0.0/0
     * in its AllowedIPs slot so wireguard-lwip will deliver internet-bound
     * packets through that peer's tunnel. The caller is also responsible
     * for steering the default route into the WG netif (e.g. via
     * ip4_route_src_hook). 0 = no exit node selected. */
    uint32_t exit_node_ip;

    /* Optional timing overrides (0 = use defaults) */
    uint32_t disco_heartbeat_ms;    /* DISCO keepalive interval (default: 3000) */
    uint32_t stun_interval_ms;      /* STUN re-probe interval (default: 23000) */
    uint32_t ctrl_watchdog_ms;      /* Control plane watchdog timeout (default: 120000) */

    /* Custom control plane host (NULL or empty = Tailscale SaaS at
     * controlplane.tailscale.com). Set to a Headscale/Ionscale URL for
     * self-hosted coordinators. Accepted forms: "host", "host:port",
     * "http://host", "http://host:port". https:// is rejected.
     * Internally clipped to 63 chars (see ml->ctrl_host[64]). */
    const char *ctrl_host;

    /* Routes the node advertises to the tailnet (Tailscale's
     * --advertise-routes equivalent). Newline-separated CIDR list, e.g.
     * "192.168.4.0/24\n192.168.1.0/24". Each route still requires admin
     * approval on the control plane before traffic actually flows.
     * NULL/empty = no routes advertised. Internally clipped to 255 chars. */
    const char *advertise_routes;

    /* Netcheck override policy.
     *   netcheck_override_enabled = false → always trust the configured
     *     default region, even when netcheck measured a faster one.
     *   netcheck_override_threshold_ms = N → only switch to the measured
     *     region when its RTT is at least N ms lower than the default
     *     region's RTT. Avoids ping-ponging on small RTT differences. */
    bool netcheck_override_enabled;
    uint32_t netcheck_override_threshold_ms;

    /* User-selected default DERP region. The control plane does NOT compute
     * its own suggestion (Tailscale Go-style: control plane just echoes
     * whatever PreferredDERP the client sent). 0 = unset → ML_DERP_REGION
     * compile-time fallback (Frankfurt). This value is also sent as
     * MapRequest.Hostinfo.NetInfo.PreferredDERP so peers know our home. */
    uint16_t preferred_derp_region;
} microlink_config_t;

/* Single CIDR route entry — used for subnet-router advertisements. */
typedef struct {
    uint32_t network;    /* network address, host byte order */
    uint8_t  prefix_len; /* CIDR prefix length, 0–32 */
} microlink_route_t;

#define MICROLINK_MAX_PEER_ROUTES 8

/* Peer info (read-only snapshot) */
typedef struct {
    uint32_t vpn_ip;
    char hostname[64];
    uint8_t public_key[32];
    bool online;
    bool direct_path;           /* true if communicating via direct UDP */
    bool is_exit_node;          /* true if peer advertises 0.0.0.0/0 in AllowedIPs */
    /* Subnet routes the peer advertises (parsed from AllowedIPs,
     * excluding the peer's own /32 in CGNAT and 0.0.0.0/0 — those
     * are reported separately). */
    microlink_route_t subnet_routes[MICROLINK_MAX_PEER_ROUTES];
    uint8_t subnet_route_count;
} microlink_peer_info_t;

/* Connection state */
typedef enum {
    ML_STATE_IDLE = 0,
    ML_STATE_WIFI_WAIT,
    ML_STATE_CONNECTING,
    ML_STATE_REGISTERING,
    ML_STATE_CONNECTED,
    ML_STATE_RECONNECTING,
    ML_STATE_ERROR,
} microlink_state_t;

/* Callback types */
typedef void (*microlink_state_cb_t)(microlink_t *ml, microlink_state_t state, void *user_data);
typedef void (*microlink_peer_cb_t)(microlink_t *ml, const microlink_peer_info_t *peer, void *user_data);
typedef void (*microlink_data_cb_t)(microlink_t *ml, uint32_t src_ip, const uint8_t *data,
                                     size_t len, void *user_data);

/**
 * @brief Factory reset — erase all stored keys and cached peers
 * @return ESP_OK on success
 *
 * Must be called BEFORE microlink_init(). Erases:
 * - Machine key, WireGuard key, DISCO key (NVS namespace "microlink")
 * - Cached peer data (NVS namespace "ml_peers")
 * After reset, next microlink_init() will generate fresh keys.
 */
esp_err_t microlink_factory_reset(void);

/**
 * @brief Initialize MicroLink
 * @param config Configuration (copied internally)
 * @return Handle on success, NULL on failure
 *
 * Creates all internal tasks, queues, and event groups.
 * Does NOT start connecting - call microlink_start() for that.
 */
microlink_t *microlink_init(const microlink_config_t *config);

/**
 * @brief Start connecting to Tailscale
 * @param ml Handle from microlink_init()
 * @return ESP_OK on success
 *
 * WiFi must be connected before calling this.
 * Connection proceeds asynchronously - use callbacks or poll state.
 */
esp_err_t microlink_start(microlink_t *ml);

/**
 * @brief Stop and disconnect from Tailscale
 * @param ml Handle
 * @return ESP_OK on success
 *
 * Gracefully shuts down all tasks and closes connections.
 */
esp_err_t microlink_stop(microlink_t *ml);

/**
 * @brief Destroy MicroLink instance and free all resources
 * @param ml Handle (NULL-safe)
 */
void microlink_destroy(microlink_t *ml);

/**
 * @brief Get current connection state
 */
microlink_state_t microlink_get_state(const microlink_t *ml);

/**
 * @brief Check if connected and ready to send/receive
 */
bool microlink_is_connected(const microlink_t *ml);

/**
 * @brief Get our assigned VPN IP
 * @return VPN IP in host byte order, 0 if not yet assigned
 */
uint32_t microlink_get_vpn_ip(const microlink_t *ml);

/**
 * @brief Pin the magicsock WG output PCB to a specific upstream netif.
 *
 * Required for exit-node mode: when netif_default is flipped to the WG
 * netif so AP-client internet traffic routes into the tunnel, the
 * encapsulated WG UDP packets must NOT loop back through that default
 * route. Calling this with the upstream (e.g. STA) netif forces the
 * raw output PCB to send only via that netif.
 *
 * Pass NULL to unpin (restores normal routing-table behaviour).
 *
 * @param ml Handle
 * @param upstream The lwIP netif to bind to (pass NULL to clear)
 * @return ESP_OK on success
 */
struct netif;
esp_err_t microlink_pin_wg_output_netif(microlink_t *ml, struct netif *upstream);

/**
 * @brief Get number of known peers
 */
int microlink_get_peer_count(const microlink_t *ml);

/**
 * @brief Get peer info by index
 * @param ml Handle
 * @param index Peer index (0 to peer_count-1)
 * @param info Output peer info (copied)
 * @return ESP_OK if valid index
 */
esp_err_t microlink_get_peer_info(const microlink_t *ml, int index, microlink_peer_info_t *info);

/* Compact runtime diagnostic snapshot for status/web UI use. */
typedef struct {
    microlink_state_t state;
    bool     connected;
    uint32_t vpn_ip;            /* tailnet CGNAT IP, host byte order */
    uint32_t wan_public_ip;     /* STUN-discovered, host byte order, 0 if unknown */
    uint16_t derp_home_region;     /* currently active DERP region (netcheck may have overridden the default) */
    uint16_t derp_region_default;  /* configured default region (user pick from /tailscale form, or ML_DERP_REGION fallback) */
    int      peer_count;
    int      peer_online;       /* peers currently marked active */
    uint32_t uptime_sec;        /* seconds in ML_STATE_CONNECTED; 0 if not connected */
} microlink_diag_t;

esp_err_t microlink_get_diag(const microlink_t *ml, microlink_diag_t *out);

/* DERP region RTT snapshot, one entry per region that responded to the
 * last netcheck. rtt_ms = 0 means the region was probed but timed out. */
typedef struct {
    uint16_t region_id;
    uint16_t rtt_ms;
} microlink_derp_rtt_t;

/* Fills `out` with up to `max` entries, ordered by ascending RTT. Returns
 * the number written (0 if no netcheck has run yet). */
int microlink_get_derp_rtts(const microlink_t *ml, microlink_derp_rtt_t *out, int max);

/* Returns the human-readable city name for a DERP region (from the
 * MapResponse DERPMap.RegionName field). Returns NULL if region_id is
 * unknown — the caller should fall through to a "?" placeholder. */
const char *microlink_get_derp_region_name(const microlink_t *ml, uint16_t region_id);

/**
 * @brief Send UDP data to a peer by VPN IP
 * @param ml Handle
 * @param dest_vpn_ip Destination VPN IP (host byte order)
 * @param data Payload
 * @param len Payload length (max 1400 bytes)
 * @return ESP_OK on success, ESP_ERR_TIMEOUT if send queue full
 */
esp_err_t microlink_send(microlink_t *ml, uint32_t dest_vpn_ip,
                          const uint8_t *data, size_t len);

/**
 * @brief Register callbacks
 */
void microlink_set_state_callback(microlink_t *ml, microlink_state_cb_t cb, void *user_data);
void microlink_set_peer_callback(microlink_t *ml, microlink_peer_cb_t cb, void *user_data);
void microlink_set_data_callback(microlink_t *ml, microlink_data_cb_t cb, void *user_data);

/**
 * @brief Convert VPN IP to string
 */
void microlink_ip_to_str(uint32_t ip, char *buf);

/**
 * @brief Parse IP string "A.B.C.D" to host byte order uint32
 * @return IP in host byte order, 0 on error
 */
uint32_t microlink_parse_ip(const char *ip_str);

/**
 * @brief Get default device name based on MAC address
 * @return Static string like "esp32-a1b2c3"
 */
const char *microlink_default_device_name(void);

/**
 * @brief Get device name based on IMEI (cellular modem)
 * @return Static string like "prefix-123456789012345", or NULL if no IMEI available
 *
 * Requires ml_cellular_init() to have been called first.
 * Returns NULL if cellular module is not initialized or IMEI not available.
 */
const char *microlink_imei_device_name(void);

/* ============================================================================
 * MagicDNS — Resolve Tailnet hostnames to VPN IPs
 *
 * Resolves short or FQDN hostnames (e.g., "npc1", "npc1.tail12345.ts.net")
 * against the known peer list. No network calls — lookup only.
 * ========================================================================== */

/**
 * @brief Resolve a tailnet hostname to its VPN IP
 * @param ml Handle
 * @param hostname Short name ("npc1") or FQDN ("npc1.tail12345.ts.net")
 * @return VPN IP in host byte order, 0 if not found
 *
 * Matching rules (in order):
 * 1. Exact match against full peer hostname
 * 2. Prefix match: "npc1" matches "npc1.tail12345.ts.net"
 * 3. Case-insensitive on all matches
 */
uint32_t microlink_resolve(const microlink_t *ml, const char *hostname);

/* ============================================================================
 * UDP Socket API
 *
 * Provides simple UDP send/receive over the Tailscale VPN tunnel.
 * Packets are routed through WireGuard for encryption.
 * ========================================================================== */

/* Opaque UDP socket handle */
typedef struct microlink_udp_socket microlink_udp_socket_t;

/* UDP receive callback (called from RX task context) */
typedef void (*microlink_udp_rx_cb_t)(microlink_udp_socket_t *sock,
                                       uint32_t src_ip, uint16_t src_port,
                                       const uint8_t *data, size_t len,
                                       void *user_data);

/**
 * @brief Create a UDP socket bound to the WireGuard VPN IP
 * @param ml Handle
 * @param local_port Port to bind (0 = auto-assign)
 * @return Socket handle, NULL on failure
 *
 * On creation, sends CallMeMaybe to all peers to trigger WG handshakes.
 */
microlink_udp_socket_t *microlink_udp_create(microlink_t *ml, uint16_t local_port);

/**
 * @brief Close UDP socket and free resources
 */
void microlink_udp_close(microlink_udp_socket_t *sock);

/**
 * @brief Send UDP data to a peer
 * @param sock Socket handle
 * @param dest_ip Destination VPN IP (host byte order)
 * @param dest_port Destination port
 * @param data Payload
 * @param len Payload length (max 1400)
 * @return ESP_OK on success
 */
esp_err_t microlink_udp_send(microlink_udp_socket_t *sock, uint32_t dest_ip,
                              uint16_t dest_port, const void *data, size_t len);

/**
 * @brief Receive UDP data (blocking with timeout)
 * @param sock Socket handle
 * @param src_ip Output source VPN IP (can be NULL)
 * @param src_port Output source port (can be NULL)
 * @param buffer Output buffer
 * @param len In: buffer size, Out: bytes received
 * @param timeout_ms Timeout in milliseconds (0 = non-blocking)
 * @return ESP_OK on success, ESP_ERR_TIMEOUT if timed out
 */
esp_err_t microlink_udp_recv(microlink_udp_socket_t *sock, uint32_t *src_ip,
                              uint16_t *src_port, void *buffer, size_t *len,
                              uint32_t timeout_ms);

/**
 * @brief Register receive callback for immediate packet handling
 * @param sock Socket handle
 * @param cb Callback (NULL to clear)
 * @param user_data Passed to callback
 */
esp_err_t microlink_udp_set_rx_callback(microlink_udp_socket_t *sock,
                                         microlink_udp_rx_cb_t cb, void *user_data);

/**
 * @brief Get local bound port
 */
uint16_t microlink_udp_get_local_port(const microlink_udp_socket_t *sock);

/* ============================================================================
 * TCP Socket API
 *
 * Provides TCP connections over the Tailscale VPN tunnel.
 * Traffic is routed through WireGuard — standard BSD TCP sockets
 * over the encrypted tunnel. Works with any TCP service on a peer
 * (HTTP, Traccar, MQTT, custom protocols, etc).
 * ========================================================================== */

/* Opaque TCP socket handle */
typedef struct microlink_tcp_socket microlink_tcp_socket_t;

/**
 * @brief Connect TCP to a peer over the VPN tunnel
 * @param ml Handle
 * @param dest_ip Destination VPN IP (host byte order)
 * @param dest_port Destination port
 * @param timeout_ms Connection timeout in ms (0 = default 15s)
 * @return Socket handle, NULL on failure
 *
 * Automatically triggers WG handshake if tunnel is not yet established.
 * Retries once if the initial connect fails due to tunnel not ready.
 */
microlink_tcp_socket_t *microlink_tcp_connect(microlink_t *ml, uint32_t dest_ip,
                                                uint16_t dest_port,
                                                uint32_t timeout_ms);

/**
 * @brief Send data over TCP connection
 * @param sock Socket handle
 * @param data Payload
 * @param len Payload length
 * @return ESP_OK on success, ESP_FAIL on error
 *
 * Blocks until all data is sent or an error occurs.
 */
esp_err_t microlink_tcp_send(microlink_tcp_socket_t *sock, const void *data, size_t len);

/**
 * @brief Receive data from TCP connection
 * @param sock Socket handle
 * @param buffer Output buffer
 * @param len Buffer size
 * @param timeout_ms Timeout in ms (0 = use socket default)
 * @return Bytes received (>0), 0 on timeout, -1 on error/disconnect
 */
int microlink_tcp_recv(microlink_tcp_socket_t *sock, void *buffer, size_t len,
                        uint32_t timeout_ms);

/**
 * @brief Check if TCP connection is still alive
 */
bool microlink_tcp_is_connected(const microlink_tcp_socket_t *sock);

/**
 * @brief Close TCP connection and free resources
 */
void microlink_tcp_close(microlink_tcp_socket_t *sock);

#ifdef __cplusplus
}
#endif
