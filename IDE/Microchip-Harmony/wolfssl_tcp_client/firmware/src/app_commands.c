/*******************************************************************************
  Sample Application

  File Name:
    app_commands.c

  Summary:
    commands for the tcp client demo app.

  Description:

 *******************************************************************************/

// DOM-IGNORE-BEGIN
/*******************************************************************************
/*
 * Copyright (C) 2006-2019 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 *******************************************************************************/
// DOM-IGNORE-END

#include "tcpip/tcpip.h"
#include "app_commands.h"
#include "app.h"
#include "config.h"
#include <cyassl/ssl.h>

#if defined(TCPIP_STACK_COMMAND_ENABLE)

extern APP_DATA appData;

static int _APP_Commands_OpenURL(SYS_CMD_DEVICE_NODE* pCmdIO, int argc, char** argv);
static int _APP_Commands_IPMode(SYS_CMD_DEVICE_NODE* pCmdIO, int argc, char** argv);
static int _APP_Commands_Stats(SYS_CMD_DEVICE_NODE* pCmdIO, int argc, char** argv);

static const SYS_CMD_DESCRIPTOR    appCmdTbl[]=
{
    {"openurl", _APP_Commands_OpenURL, ": Connect to a url and do a GET"},
    {"ipmode", _APP_Commands_IPMode, ": Change IP Mode"},
    {"stats", _APP_Commands_Stats, ": Statistics"},
};

bool APP_Commands_Init()
{
    if (!SYS_CMD_ADDGRP(appCmdTbl, sizeof(appCmdTbl)/sizeof(*appCmdTbl), "app", ": app commands"))
    {
        SYS_ERROR(SYS_ERROR_ERROR, "Failed to create TCPIP Commands\r\n", 0);
        return false;
    }

    return true;
}

int _APP_Commands_OpenURL(SYS_CMD_DEVICE_NODE* pCmdIO, int argc, char** argv)
{
    const void* cmdIoParam = pCmdIO->cmdIoParam;

    if (argc != 2)
    {
        (*pCmdIO->pCmdApi->msg)(cmdIoParam, "Usage: openurl <url>\r\n");
        (*pCmdIO->pCmdApi->msg)(cmdIoParam, "Ex: openurl http://www.google.com/\r\n");
        return true;
    }
    if (appData.state != APP_TCPIP_WAITING_FOR_COMMAND)
    {
        (*pCmdIO->pCmdApi->msg)(cmdIoParam, "Demo is in the wrong state to take this command");
        return true;
    }
    appData.state = APP_TCPIP_PROCESS_COMMAND;
    strncpy(appData.urlBuffer, argv[1], sizeof(appData.urlBuffer));
    return false;
}

extern APP_DATA appData;

int _APP_Commands_IPMode(SYS_CMD_DEVICE_NODE* pCmdIO, int argc, char** argv)
{
    const void* cmdIoParam = pCmdIO->cmdIoParam;
    if (argc != 2)
    {
        (*pCmdIO->pCmdApi->msg)(cmdIoParam, "Usage: ipmode <ANY|4|6>\r\n");
        (*pCmdIO->pCmdApi->msg)(cmdIoParam, "Ex: ipmode 6\r\n");
        return true;

    }
    appData.ipMode = atoi(argv[1]);
    return true;
}

int _APP_Commands_Stats(SYS_CMD_DEVICE_NODE* pCmdIO, int argc, char** argv)
{
    const void* cmdIoParam = pCmdIO->cmdIoParam;

    (*pCmdIO->pCmdApi->print)(cmdIoParam, "Raw Bytes Txed: %d\r\n", appData.rawBytesSent);
    (*pCmdIO->pCmdApi->print)(cmdIoParam, "Raw Bytes Rxed: %d\r\n", appData.rawBytesReceived);
    (*pCmdIO->pCmdApi->print)(cmdIoParam, "Clear Bytes Txed: %d\r\n", appData.clearBytesSent);
    (*pCmdIO->pCmdApi->print)(cmdIoParam, "Clear Bytes Rxed: %d\r\n", appData.clearBytesReceived);

    uint32_t freq = SYS_TMR_SystemCountFrequencyGet();
    uint32_t time = ((appData.dnsComplete - appData.testStart) * 1000ull) / freq;
    (*pCmdIO->pCmdApi->print)(cmdIoParam, "DNS Lookup Time: %d ms\r\n", time);

    time = ((appData.connectionOpened - appData.dnsComplete) * 1000ull) / freq;
    (*pCmdIO->pCmdApi->print)(cmdIoParam, "Time to Start TCP Connection: %d ms\r\n", time);

    if (appData.urlBuffer[4] == 's')
    {
        time = ((appData.sslNegComplete - appData.connectionOpened) * 1000ull) / freq;
        (*pCmdIO->pCmdApi->print)(cmdIoParam, "Time to Negotiate SSL Connection: %d ms\r\n", time);

        time = ((appData.firstRxDataPacket - appData.sslNegComplete) * 1000ull) / freq;
        (*pCmdIO->pCmdApi->print)(cmdIoParam, "Time to till first packet from server: %d ms\r\n", time);
    }
    else
    {
        time = ((appData.firstRxDataPacket - appData.connectionOpened) * 1000ull) / freq;
        (*pCmdIO->pCmdApi->print)(cmdIoParam, "Time for first packet from server: %d ms\r\n", time);
    }

    time = ((appData.lastRxDataPacket - appData.firstRxDataPacket) * 1000ull) / freq;
    (*pCmdIO->pCmdApi->print)(cmdIoParam, "Time for last packet from server: %d ms\r\n", time);
    return true;
}

#endif
