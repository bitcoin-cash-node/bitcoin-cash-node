// Copyright (c) 2015 The Bitcoin Core developers
// Copyright (c) 2017-2026 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <sync.h>

#include <chrono>
#include <functional>
#include <list>
#include <map>
#include <thread>
#include <utility>

//
// Simple class for background tasks that should be run periodically or once
// "after a while"
//
// Usage:
//
// CScheduler* s = new CScheduler();
// s->scheduleFromNow(doSomething, 11); // Assuming a: void doSomething(int) { }
// s->scheduleFromNow(std::bind(Class::func, this, argument), 3);
// s->scheduleFromNow([this](int argument) { this->func(argument); }, 3);
// std::thread t = std::thread(CScheduler::serviceQueue, s);
//
// ... then at program shutdown, clean up the thread running serviceQueue:
// t.join();
//

class CScheduler {
public:
    CScheduler();
    ~CScheduler();

    std::thread serviceThread;

    using Function = std::function<void()>;
    using Predicate = std::function<bool()>;

    // Call func at/after time t
    void schedule(Function f, std::chrono::system_clock::time_point t = std::chrono::system_clock::now());

    // Convenience method: call f once deltaMilliSeconds from now
    void scheduleFromNow(Function f, int64_t deltaMilliSeconds);
    // Helper for above that uses a chrono type
    void scheduleFromNow(Function f, std::chrono::milliseconds ms) {
        scheduleFromNow(std::move(f), static_cast<int64_t>(ms.count()));
    }

    // Another convenience method: call p approximately every deltaMilliSeconds
    // forever, starting deltaMilliSeconds from now untill p returns false. To
    // be more precise: every time p is finished, it is rescheduled to run
    // deltaMilliSeconds later. If you need more accurate scheduling, don't use
    // this method.
    void scheduleEvery(Predicate p, int64_t deltaMilliSeconds);
    // Helper for above that uses a chrono type
    void scheduleEvery(Predicate p, std::chrono::milliseconds msec) {
        scheduleEvery(std::move(p), static_cast<int64_t>(msec.count()));
    }

    /**
     * Mock the scheduler to fast forward in time.
     * Iterates through items on taskQueue and reschedules them
     * to be delta_seconds sooner.
     */
    void MockForward(std::chrono::seconds delta_seconds);

    // To keep things as simple as possible, there is no unschedule.

    // Services the queue 'forever'. Should be run in a thread.
    void serviceQueue();

    // Tell any threads running serviceQueue to stop as soon as they're done
    // servicing whatever task they're currently servicing (drain=false) or when
    // there is no work left to be done (drain=true)
    void stop(bool drain = false);

    // Returns number of tasks waiting to be serviced, and first and last task
    // times
    size_t getQueueInfo(std::chrono::system_clock::time_point &first,
                        std::chrono::system_clock::time_point &last) const;

    // Returns true if there are threads actively running in serviceQueue()
    bool AreThreadsServicingQueue() const;

private:
    std::multimap<std::chrono::system_clock::time_point, Function> taskQueue;
    std::condition_variable newTaskScheduled;
    mutable std::mutex newTaskMutex;
    int nThreadsServicingQueue;
    bool stopRequested;
    bool stopWhenEmpty;
    bool shouldStop() const {
        return stopRequested || (stopWhenEmpty && taskQueue.empty());
    }
};

/**
 * Class used by CScheduler clients which may schedule multiple jobs
 * which are required to be run serially. Jobs may not be run on the
 * same thread, but no two jobs will be executed
 * at the same time and memory will be release-acquire consistent
 * (the scheduler will internally do an acquire before invoking a callback
 * as well as a release at the end). In practice this means that a callback
 * B() will be able to observe all of the effects of callback A() which executed
 * before it.
 */
class SingleThreadedSchedulerClient {
private:
    CScheduler *m_pscheduler;

    RecursiveMutex m_cs_callbacks_pending;
    std::list<CScheduler::Function> m_callbacks_pending GUARDED_BY(m_cs_callbacks_pending);
    bool m_are_callbacks_running GUARDED_BY(m_cs_callbacks_pending) = false;

    void MaybeScheduleProcessQueue();
    void ProcessQueue();

public:
    explicit SingleThreadedSchedulerClient(CScheduler *pschedulerIn) : m_pscheduler(pschedulerIn) {}

    /**
     * Add a callback to be executed. Callbacks are executed serially
     * and memory is release-acquire consistent between callback executions.
     * Practially, this means that callbacks can behave as if they are executed
     * in order by a single thread.
     */
    void AddToProcessQueue(CScheduler::Function func);

    // Processes all remaining queue members on the calling thread, blocking
    // until queue is empty. Must be called after the CScheduler has no
    // remaining processing threads!
    void EmptyQueue();

    size_t CallbacksPending();
};
