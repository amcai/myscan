#!/usr/bin/env python3
# @Time    : 2020-02-14
# @Author  : caicai
# @File    : threads.py
import threading
# import traceback
from queue import Queue
from myscan.lib.core.data import logger
from myscan.lib.core.data import cmd_line_options


def mythread(func, mapslist, thread_num=None):
    threads = []
    queue = Queue()
    for i in mapslist:
        queue.put(i)
    if thread_num is None:
        thread_num = cmd_line_options.threads
    for x in range(0, int(thread_num)):
        threads.append(tThread(queue, func))

    for t in threads:
        t.start()
    for t in threads:
        t.join()


class tThread(threading.Thread):
    def __init__(self, queue, func):
        threading.Thread.__init__(self)
        self.queue = queue
        self.func = func

    def run(self):

        while not self.queue.empty():
            arg = self.queue.get()
            try:
                self.func(arg)
            except Exception as e:
                logger.warning("run thread error:{}".format(str(e)))
                # traceback.print_exc()
