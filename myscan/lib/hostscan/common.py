from myscan.lib.core.data import logger
import subprocess


def get_data_from_file(filename):
    lines = []
    try:
        with open(filename, errors="ignore") as f:
            for line in f:
                line = line.strip()
                if line:
                    lines.append(line)
    except Exception as ex:
        logger.warning("get_data_from_file get error:{}".format(ex))
    return lines


# def get_class_from_jvm(jarpath,classname):
#     if not jpype.isJVMStarted():
#         jvm_path = jpype.getDefaultJVMPath()
#         jpype.startJVM(jvm_path, "-Djava.class.path={}".format(jarpath),
#                        convertStrings=True)
#     javaClass = jpype.JClass(classname)
#     return javaClass
def start_process(args: list, timeout: int = 30):
    try:
        ret = subprocess.check_output(args, timeout)
    except subprocess.CalledProcessError as ex:
        return ex.output  # Output generated before error
    return ret
