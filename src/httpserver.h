// Copyright (c) 2015-2016 The Bitcoin Core developers
// Copyright (c) 2018-2023 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <span.h>

#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

/**
 * The default value for `-rpcthreads`. This number of threads will be created at startup.
 */
static constexpr int DEFAULT_HTTP_THREADS = 16;

/**
 * The default value for `-rpcworkqueue`. This is the maximum depth of the work queue,
 * we don't allocate this number of work queue items upfront.
 */
static constexpr int DEFAULT_HTTP_WORKQUEUE = 64;

static const int DEFAULT_HTTP_SERVER_TIMEOUT = 30;

struct evhttp_request;
struct event_base;

class Config;
class CService;
class HTTPRequest;

/**
 * Initialize HTTP server.
 * Call this before RegisterHTTPHandler or EventBase().
 */
bool InitHTTPServer(Config &config);

/**
 * Start HTTP server.
 * This is separate from InitHTTPServer to give users race-condition-free time
 * to register their handlers between InitHTTPServer and StartHTTPServer.
 */
void StartHTTPServer();

/** Interrupt HTTP server threads */
void InterruptHTTPServer();

/** Stop HTTP server */
void StopHTTPServer();

/**
 * Change logging level for libevent. Removes BCLog::LIBEVENT from
 * log categories if libevent doesn't support debug logging.
 */
bool UpdateHTTPServerLogging(bool enable);

/** Handler for requests to a certain HTTP path */
typedef std::function<bool(Config &config, HTTPRequest *req,
                           const std::string &)>
    HTTPRequestHandler;

/**
 * Register handler for prefix.
 * If multiple handlers match a prefix, the first-registered one will
 * be invoked.
 */
void RegisterHTTPHandler(const std::string &prefix, bool exactMatch,
                         const HTTPRequestHandler &handler);

/** Unregister handler for prefix */
void UnregisterHTTPHandler(const std::string &prefix, bool exactMatch);

/**
 * Return evhttp event base. This can be used by submodules to
 * queue timers or custom events.
 */
struct event_base *EventBase();

/**
 * In-flight HTTP request.
 * Thin C++ wrapper around evhttp_request.
 */
class HTTPRequest {
    struct evhttp_request *req;
    bool replySent;

public:
    explicit HTTPRequest(struct evhttp_request *req);
    ~HTTPRequest();

    enum RequestMethod { UNKNOWN, GET, POST, HEAD, PUT, OPTIONS };

    /** Get requested URI */
    std::string GetURI() const;

    /** Get CService (address:ip) for the origin of the http request */
    CService GetPeer() const;

    /** Get request method */
    RequestMethod GetRequestMethod() const;

    /**
     * Get the request header specified by hdr.
     * @return The header's value, if present, or a std::nullopt if the header
     * was not present.
     */
    std::optional<std::string> GetHeader(const std::string &hdr) const;

    //! A vector of these is returned by GetAll*Headers.
    using NameValuePair = std::pair<std::string, std::string>;

    /**
     *  Get the entire header contents for the request. This is all of the
     *  headers sent to us by the client.
     */
    std::vector<NameValuePair> GetAllInputHeaders() const { return GetAllHeaders(true); }

    /**
     *  Get the entire header contents for the reply. This is all of the
     *  headers enqueued for sending to the client via previous calls to
     *  WriteHeader().
     */
    std::vector<NameValuePair> GetAllOutputHeaders() const { return GetAllHeaders(false); }

    /**
     * Read request body.
     *
     * @param drain - If set to true, consume the underlying buffer.
     * @note Specifying drain = true will consume the underlying buffer,
     * so call it this way only once. Repeated calls after a drain = true
     * call will always return an empty string.
     */
    std::string ReadBody(bool drain = true);

    /**
     * Write output header.
     *
     * @note call this before calling WriteErrorReply or Reply.
     */
    void WriteHeader(const std::string &hdr, const std::string &value);

    /**
     * Write HTTP reply.
     * nStatus is the HTTP status code to send.
     * reply is the body of the reply. Keep it empty to send a standard
     * message.
     *
     * @note Can be called only once. As this will give the request back to the
     * main thread, do not call any other HTTPRequest methods after calling
     * this.
     */
    void WriteReply(int nStatus, Span<const uint8_t> reply = {});
    void WriteReply(int nStatus, std::string_view reply) { WriteReply(nStatus, MakeUInt8Span(reply)); }

private:
    std::vector<NameValuePair> GetAllHeaders(bool input) const;
};

/** Event handler closure */
class HTTPClosure {
public:
    virtual void operator()() = 0;
    virtual ~HTTPClosure() {}
};

/**
 * Event class. This can be used either as a cross-thread trigger or as a
 * timer.
 */
class HTTPEvent {
public:
    /**
     * Create a new event.
     * deleteWhenTriggered deletes this event object after the event is
     * triggered (and the handler called)
     * handler is the handler to call when the event is triggered.
     */
    HTTPEvent(struct event_base *base, bool deleteWhenTriggered,
              const std::function<void()> &handler);
    ~HTTPEvent();

    /**
     * Trigger the event. If tv is 0, trigger it immediately. Otherwise trigger
     * it after the given time has elapsed.
     */
    void trigger(struct timeval *tv);

    bool deleteWhenTriggered;
    std::function<void()> handler;

private:
    struct event *ev;
};
