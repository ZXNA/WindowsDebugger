#pragma once
#include "stdafx.h"

//界面头
void SoftPage(void);
//根据用户的输入调用相应的API
void SelInvokApi(void);
//接收调试事件
void RecvExceptionInfo(void);
//处理异常信息
DWORD OnException(EXCEPTION_RECORD* pExcept);
