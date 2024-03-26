/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: Copyright (C) 2024, Advanced Micro Devices, Inc. */

#include <array>
#include <cassert>

template <typename T, const size_t capacity> class static_stack {
public:
  static_stack() : head{capacity} {}

  T &&pop() {
    assert(!empty());
    return std::move(arr[head++]);
  }

  T &top() const {
    assert(!empty());
    return arr[head];
  }

  void push(T &&value) {
    assert(size() < capacity);
    arr[--head] = value;
  }

  void push(T &value) {
    assert(size() < capacity);
    arr[--head] = value;
  }

  bool empty() const { return head == capacity; }

  size_t size() const { return (size_t)(capacity - head); }

  bool full() const { return size() == capacity; }

  constexpr size_t get_capacity() const { return capacity; }

  const T *begin() const { return &arr[head]; }

  const T *end() const {
    return static_cast<const T *>(&arr[capacity - 1]) + 1;
  }

private:
  size_t head = capacity - 1;
  std::array<T, capacity> arr{};
};

template <typename T, const size_t capacity> class static_queue_iter {
public:
  static_queue_iter(const std::array<T, capacity> &arr_, size_t ptr_)
      : arr{arr_}, ptr{ptr_} {}

  bool operator==(static_queue_iter<T, capacity> i) { return ptr == i.ptr; }

  bool operator!=(static_queue_iter<T, capacity> i) { return ptr != i.ptr; }

  static_queue_iter &operator++() {
    ptr++;
    return *this;
  }

  const T &operator*() const { return arr[ptr % capacity]; }

private:
  const std::array<T, capacity> &arr;
  size_t ptr;
};

template <typename T, const size_t capacity> class static_queue {
public:
  static_queue() : added{0}, removed{0} {}

  T &&deq() {
    assert(!empty());
    return std::move(arr[removed++ % capacity]);
  }

  T &front() {
    assert(!empty());
    return arr[removed % capacity];
  }

  void enq(T &value) {
    assert(added - removed < capacity);
    arr[added++ % capacity] = value;
  }

  void enq(T &&value) {
    assert(added - removed < capacity);
    arr[added++ % capacity] = std::move(value);
  }

  bool empty() { return added == removed; }

  size_t size() {
    assert(added >= removed);
    return added - removed;
  }

  bool full() { return size() == capacity; }

  constexpr size_t get_capacity() const { return capacity; }

  static_queue_iter<T, capacity> begin() const {
    return static_queue_iter<T, capacity>{arr, removed};
  }

  static_queue_iter<T, capacity> end() const {
    return static_queue_iter<T, capacity>{arr, added};
  }

private:
  size_t added{}, removed{};
  std::array<T, capacity> arr;
};

