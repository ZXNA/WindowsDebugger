#pragma once
#include "stdafx.h"

//����ͷ
void SoftPage(void);
//�����û������������Ӧ��API
void SelInvokApi(void);
//���յ����¼�
void RecvExceptionInfo(void);
//�����쳣��Ϣ
DWORD OnException(EXCEPTION_RECORD* pExcept);
