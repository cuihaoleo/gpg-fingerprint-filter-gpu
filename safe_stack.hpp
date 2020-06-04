#ifndef _SAFE_STACK_HPP_
#define _SAFE_STACK_HPP_

#include <deque>
#include <mutex>
#include <condition_variable>

template <typename T>
class SafeStack {
private:
    using size_type = typename std::deque<T>::size_type;

    std::deque<T> stack;
    size_type max_size;

    std::mutex mutex;
    std::condition_variable cond_var_push;
    std::condition_variable cond_var_pop;

public:
    explicit SafeStack(size_type size): max_size(size) { };

    SafeStack(const SafeStack&) = delete;

    void push(const T &item) {
        std::unique_lock<std::mutex> lock(mutex);
        cond_var_push.wait(lock, [=]{ return !full(); });

        stack.push_back(item);

        lock.unlock();
        cond_var_pop.notify_one();
    }

    T pop() {
        std::unique_lock<std::mutex> lock(mutex);
        cond_var_pop.wait(lock, [=]{ return !empty(); });

        T ret(std::move(stack.back()));
        stack.pop_back();

        lock.unlock();
        cond_var_push.notify_one();

        return ret;
    }

    bool empty() {
        return stack.size() == 0;
    }

    bool full() {
        return stack.size() >= max_size;
    }
};

#endif
