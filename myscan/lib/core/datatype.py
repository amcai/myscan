#!/usr/bin/env python3
# @Time    : 2020-02-14
# @Author  : caicai
# @File    : datatype.py
from collections import OrderedDict
import copy
import types

class AttribDict(OrderedDict):
    """
    AttrDict extends OrderedDict to provide attribute-style access.
    Items starting with __ or _OrderedDict__ can't be accessed as attributes.
    """
    __exclude_keys__ = set()

    def __getattr__(self, name):
        if (name.startswith('__')
                or name.startswith('_OrderedDict__')
                or name in self.__exclude_keys__):
            return super(AttribDict, self).__getattribute__(name)
        else:
            try:
                return self[name]
            except KeyError:
                raise AttributeError(name)

    def __setattr__(self, name, value):
        if (name.startswith('__')
                or name.startswith('_OrderedDict__')
                or name in self.__exclude_keys__):
            return super(AttribDict, self).__setattr__(name, value)
        self[name] = value

    def __delattr__(self, name):
        if (name.startswith('__')
                or name.startswith('_OrderedDict__')
                or name in self.__exclude_keys__):
            return super(AttribDict, self).__delattr__(name)
        del self[name]
    def __getstate__(self):
        return self.__dict__

    def __setstate__(self, dict):
        self.__dict__ = dict

    # def __deepcopy__(self, memo):
    #     retVal = self.__class__()
    #     memo[id(self)] = retVal
    #
    #     for attr in dir(self):
    #         if not attr.startswith('_'):
    #             value = getattr(self, attr)
    #             if not isinstance(value, (types.BuiltinFunctionType, types.FunctionType, types.MethodType)):
    #                 setattr(retVal, attr, copy.deepcopy(value, memo))
    #
    #     for key, value in self.items():
    #         retVal.__setitem__(key, copy.deepcopy(value, memo))
    #
    #     return retVal
