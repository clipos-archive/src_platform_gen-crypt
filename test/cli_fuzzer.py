#!/usr/bin/python
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: LGPL-2.1-or-later
# Copyright © 2008-2018 ANSSI. All Rights Reserved.

import sys
import os
import subprocess

def build_cmd_opt_list(prog, opt_list):
    # au moins une option
    ok_list = []
    nok_list = []

    # index_list is initialized with the number of possible values for each
    # options of the list
    opt_nb = len(opt_list)
    index_list = []
    for i in range(0, opt_nb):
        index_list.append(len(opt_list[i][2]) - 1)

    # now we go through the possibilities using index_list as our counter:
    # if the index in index_list is realistic, take the option,
    # if it is -1, do not select the option
    cmd = ""
    current_ok = True

    while True :
        # build the command
        for i in range(0, opt_nb):
            if index_list[i] == -1:
                # this encodes the case when we do not select the option. Just
                # look at whether it is required to capture that a cmd without
                # this option cannot be OK
                if opt_list[i][1] == "required":
                    current_ok = False
            else:
                # this encodes that we do take the index_list[i]-th
                # possible value for the option
                opt = opt_list[i][0] # string designating the option
                opt_args = opt_list[i][2] # possible values of the option
                # get the pair argument
                (arg_char, arg_val) = opt_args[index_list[i]]
                if opt == "":
                    cmd = arg_val + " " + cmd
                else:
                    cmd = opt + " " + arg_val + " " + cmd
                if arg_char == "bad":
                    current_ok = False
                # else we do nothing and current_ok keeps its current value

        # cmd complete, pile it up on the right list:
        if current_ok:
            ok_list = [cmd] + ok_list
        else:
            nok_list = [cmd] + nok_list

        # print cmd, current_ok
        cmd = ""
        current_ok = True

        # get next iterator.
        j = opt_nb - 1
        while (j >= 0):
            if index_list[j] == -1:
                j = j - 1
            else:
                index_list[j] = index_list[j] - 1
                for column in range(j + 1, opt_nb):
                    index_list[column] = len(opt_list[column][2]) - 1
                break
        if j == -1:
            break

    print "List of command options built\n"
    return (ok_list, nok_list);

def exec_list(command, cmd_list, expected, log_file):
    sys.stdout = log_file
    sys.stderr = log_file

    for args in cmd_list:
        cmd = command + " " + args
        print "Running: {}".format(cmd)
        sys.stdout.flush()
        ret = subprocess.call(cmd, stdout = log_file, stderr = log_file, shell = True)
        sys.stdout.flush()
        sys.stderr.flush()
        if ret != expected:
            # If we expect a bad argument returne code (ret == 10), then both 1
            # and 10 are accepted as return code as some strange combination of
            # invalid arguments could lead to valid calls with invalid
            # arguments.
            if ret == 10 and expected != 1:
                print "Running: {}: returned: {}".format(cmd, ret)
                sys.stdout = sys.__stdout__
                sys.stderr = sys.__stderr__
                return False

    sys.stdout = sys.__stdout__
    sys.stderr = sys.__stderr__
    return True

#list_test=[("-h", "compulsory", [("good", "")]), \
#("-k","optional",[("good","keys/dev.pvr"), ("bad","keys/po"), ("bad", "../../"), ("bad", "")]), \
#("-y", "optional", [("good", "blah")])]
#(ok_cmd, nok_cmd) = build_cmd_list("blah", list_test)
#print "OK cmds", ok_cmd
#print "NOK cmds", nok_cmd
