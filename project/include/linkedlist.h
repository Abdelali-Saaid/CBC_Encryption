#ifndef LINKEDLIST_H
#define LINKEDLIST_H

struct Node {
    char data;
    struct Node *next;
};

struct Node *createNode(char data);
void appendNode(struct Node **head, char data);
void displayList(struct Node *head);
void freeList(struct Node *head);

#endif
