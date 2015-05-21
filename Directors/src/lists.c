//
//  lists.c
//
//
//  Created by Benjamin Sinclair on 4/05/2015.
//
//

#include "directors.h"

node_t *create_list(INFO *info)
{
    node_t *head = NULL;
    head = malloc(sizeof(node_t));
    head->info = info;
    head->next = NULL;
    return head;
}

int *add_entry(node_t *head, INFO *info)
{
    node_t *current = head;
    while(current->next != NULL) {
        current = current->next;
    }
    
    current->next = malloc(sizeof(node_t));
    current->next->info = info;
    current->next->next = NULL;
    return 0;
}

INFO *check_match(node_t *head, char service_type)
{
    node_t *current = head;
    while(current != NULL) {
        if(current->info->service_type == service_type) {
            return current->info;
        }
        current = current->next;
    }
    return NULL;
}

INFO *get_next_entry(node_t **head)
{
    if((*head) == NULL) {
        return NULL;
    }
    if((*head)->next == NULL) {
        return NULL;
    }
    (*head) = (*head)->next;
    INFO *next = (*head)->info;
    head++;
    return next;
}

int remove_entry(node_t *head, int client_id)
{
    node_t *current = head;
    node_t *temp = NULL;
    if(current == NULL) {
        return -1;
    }
    if(current->info->client_id == client_id) {
        node_t *next_node = head->next;
        free(head);
        head = next_node;
        return 0;
    }
    while(current->next != NULL) {
        if(current->next->info->client_id == client_id) {
            break;
        }
        current = current->next;
    }
    temp = current->next;
    current->next = temp->next;
    free(temp);
    
    return 0;
}
