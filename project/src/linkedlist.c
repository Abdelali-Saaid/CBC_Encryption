#include "../include/linkedlist.h"
#include <stdlib.h>
#include <stdio.h>

struct Node *createNode(char data) {
    struct Node *newNode = (struct Node *)malloc(sizeof(struct Node));
    if (!newNode) return NULL;
    newNode->data = data;
    newNode->next = NULL;
    return newNode;
}

void appendNode(struct Node **head, char data) {
    struct Node *newNode = createNode(data);
    if (!newNode) return;
    
    if (*head == NULL) {
        *head = newNode;
        return;
    }
    
    struct Node *current = *head;
    while (current->next != NULL) {
        current = current->next;
    }
    current->next = newNode;
}

void displayList(struct Node *head) {
    struct Node *current = head;
    while (current != NULL) {
        printf("%c", current->data);
        current = current->next;
    }
    printf("\n");
}

void freeList(struct Node *head) {
    struct Node *current = head;
    while (current != NULL) {
        struct Node *temp = current;
        current = current->next;
        free(temp);
    }
}
