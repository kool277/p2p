//! A very small task runner. Store operations are effects that a host completes later
//! (ADR-0002, part 5), so a login is many steps apart in time. Writing those steps as
//! `async` functions keeps them readable, and nothing here needs a runtime: a task runs
//! whenever `Inner::run_ready` is called, which the host's effect loop does.

use std::collections::{HashMap, HashSet, VecDeque};
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Condvar, Mutex, Weak};
use std::task::{Context, Poll, Wake, Waker};

/// A task's future.
pub(crate) type BoxFuture = Pin<Box<dyn Future<Output = ()> + Send>>;

#[derive(Default)]
struct Queue {
    next_id: u64,
    tasks: HashMap<u64, BoxFuture>,
    ready: VecDeque<u64>,
    running: HashSet<u64>,
    woken_while_running: HashSet<u64>,
}

/// Runs tasks. Cloning shares the same queue.
#[derive(Default)]
pub(crate) struct Executor {
    queue: Mutex<Queue>,
    /// Signalled whenever a task becomes ready or a host effect appears.
    pub(crate) activity: Condvar,
    pub(crate) activity_lock: Mutex<()>,
}

struct TaskWaker {
    id: u64,
    executor: Weak<Executor>,
}

impl Wake for TaskWaker {
    fn wake(self: Arc<Self>) {
        if let Some(executor) = self.executor.upgrade() {
            executor.mark_ready(self.id);
        }
    }
}

impl Executor {
    fn mark_ready(&self, id: u64) {
        let mut queue = self.queue.lock().unwrap_or_else(|e| e.into_inner());
        if queue.running.contains(&id) {
            queue.woken_while_running.insert(id);
        } else if queue.tasks.contains_key(&id) {
            queue.ready.push_back(id);
        }
        drop(queue);
        self.notify();
    }

    pub(crate) fn notify(&self) {
        let _guard = self.activity_lock.lock().unwrap_or_else(|e| e.into_inner());
        self.activity.notify_all();
    }

    /// Adds a task and marks it ready.
    pub(crate) fn spawn(&self, task: BoxFuture) {
        let mut queue = self.queue.lock().unwrap_or_else(|e| e.into_inner());
        let id = queue.next_id;
        queue.next_id += 1;
        queue.tasks.insert(id, task);
        queue.ready.push_back(id);
    }

    /// Polls every ready task until none is left.
    pub(crate) fn run_ready(self: &Arc<Self>) {
        loop {
            let (id, mut task) = {
                let mut queue = self.queue.lock().unwrap_or_else(|e| e.into_inner());
                let mut found = None;
                while let Some(id) = queue.ready.pop_front() {
                    if let Some(task) = queue.tasks.remove(&id) {
                        queue.running.insert(id);
                        found = Some((id, task));
                        break;
                    }
                }
                match found {
                    Some(f) => f,
                    None => return,
                }
            };
            let waker = Waker::from(Arc::new(TaskWaker {
                id,
                executor: Arc::downgrade(self),
            }));
            let mut context = Context::from_waker(&waker);
            let finished = matches!(task.as_mut().poll(&mut context), Poll::Ready(()));

            let mut queue = self.queue.lock().unwrap_or_else(|e| e.into_inner());
            queue.running.remove(&id);
            let woken = queue.woken_while_running.remove(&id);
            if !finished {
                queue.tasks.insert(id, task);
                if woken {
                    queue.ready.push_back(id);
                }
            }
        }
    }
}
