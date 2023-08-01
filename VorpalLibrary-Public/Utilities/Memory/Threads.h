/**
* Copyright (C) 2023 Vorpal. All rights reserved.
*
* Licensed under the Vorpal Library Software License. You may obtain a copy
* in the file "LICENSE" found at the root of this repository.
*/

#pragma once
#include <queue>

namespace VorpalAPI {
	namespace Memory {
		namespace Threads {

			class Thread {
			private:
				std::string m_name;
				HANDLE m_thread;
				bool m_isRunning;

			public:
				Thread() : m_name(""), m_thread(0), m_isRunning(true) {}
				Thread(std::string name) : m_name(name), m_thread(0), m_isRunning(true) {}
				void setHandle(HANDLE handle) { m_thread = handle; }
				HANDLE getHandle() { return m_thread; };
				void shutdown() { m_isRunning = false; };
				void destroy() { TerminateThread(m_thread, 0); };
				bool isRunning() { return m_isRunning; }
				std::string getName() { return m_name; }
			};

			class ThreadPool {
			public:

				/*~ThreadPool() {
					this->Cleanup();
				}*/

				void Initialize(int threads);
				void Cleanup();
				void DoJob(std::function <void(void)> func);
				bool IsInitialized() { return m_initialized; }
				Thread* RegisterThread(std::string name, void(*func)());
				std::vector<Thread*> GetThreads() { return m_threads; };

			private:
				std::vector<Thread*> m_threads;
				std::vector <std::thread> m_jobThreads;

				bool m_shutdown = false;
				bool m_initialized = false;

				std::mutex m_lock;
				std::condition_variable m_conditionVariable;
				std::queue<std::function<void(void)>> m_jobs;

				void ThreadEntry(int index);
			};

			ThreadPool* GetThreadPool();
		}
	}
}