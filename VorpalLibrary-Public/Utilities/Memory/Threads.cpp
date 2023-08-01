/**
* Copyright (C) 2023 Vorpal. All rights reserved.
*
* Licensed under the Vorpal Library Software License. You may obtain a copy
* in the file "LICENSE" found at the root of this repository.
*/

#include "common.h"
#include "Threads.h"

namespace VorpalAPI {
	namespace Memory {
		namespace Threads {

			static ThreadPool g_pool;

			void ThreadPool::Initialize(int threads) {
				if (m_initialized) return;

				m_initialized = true;
				m_jobThreads.reserve(threads);

				for (int i = 0; i < threads; ++i)
					m_jobThreads.emplace_back(std::bind(&ThreadPool::ThreadEntry, this, i));

				LOG("[Threads] Thread pool created");
			}

			void ThreadPool::Cleanup() {
				std::unique_lock <std::mutex> l(m_lock);

				m_shutdown = true;
				m_conditionVariable.notify_all();

				for (auto& c_thread : m_threads) {
					c_thread->shutdown();
					//delete c_thread;
				}
				for (auto& c_thread : m_jobThreads)
					c_thread.join();

				LOG("[Threads] Thread pool terminated");
			}

			void ThreadPool::DoJob(std::function <void(void)> func) {
				if (!m_initialized) {
					LOG("[Threads] Thread pool has not been initialized");
					return;
				}
				std::unique_lock <std::mutex> l(m_lock);
				m_jobs.emplace(std::move(func));
				m_conditionVariable.notify_one();
			}

			void ThreadPool::ThreadEntry(int index) {
				std::function<void(void)> job;
				while (1) {
					{
						std::unique_lock <std::mutex> lock(m_lock);
						while (!m_shutdown && m_jobs.empty()) m_conditionVariable.wait(lock);
						if (m_jobs.empty())return;
						job = std::move(m_jobs.front());
						m_jobs.pop();
					}
					job();
				}
			}

			Thread* ThreadPool::RegisterThread(std::string name, void(*func)()) {
				Thread* c_thread = new Thread(name);
				uint64_t* args = new uint64_t[3]{ 0, (uint64_t)c_thread, (uint64_t)func };

				c_thread->setHandle(CreateThread(0, 0, [](LPVOID lpFiberParameter) -> DWORD {
					uint64_t* arguments = (uint64_t*)lpFiberParameter;
					try {
						while ((*(Thread*)arguments[1]).isRunning()) {
							((void(*)(void)) arguments[2])();
						}
					}
					catch (...) {
						delete[] arguments;
					}
					return 1;
				}, args, 0, 0));

				hash_NtSetInformationThread(c_thread->getHandle(), 17, 0, 0);
				
				m_threads.push_back(c_thread);
				LOG("[Threads] %s registered", name);
				return c_thread;
			}

			ThreadPool* GetThreadPool() {
				return &g_pool;
			}
		}
	}
}