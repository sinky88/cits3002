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
    printf("Service type is %i\n", current->info->service_type);
    while(current != NULL) {
        if(current->info->service_type == service_type) {
            return current->info;
        }
        current = current->next;
    }
    return NULL;
}


int remove_entry(node_t *head, int client_id)
{
    node_t *current = head;
    node_t *temp = NULL;
    if(current == NULL) {
        return -1;
    }
    if(current->info->client_id == client_id) {
        printf("Found entry to remove!\n");
        node_t *next_node = head->next;
        free(head);
        head = next_node;
        return 0;
    }
    while(current->next != NULL) {
        if(current->next->info->client_id == client_id) {
            printf("Found entry to remove!\n");
            break;
        }
        current = current->next;
    }
    temp = current->next;
    current->next = temp->next;
    free(temp);
    
    return 0;
}

/*
int add_entry(INFO **info, INFO *info_entry, int *info_count)
{
    info = info + (*info_count);
    (*info) = info_entry;
    info = info - (*info_count);
    *info_count = *info_count + 1;
    return 0;
}

INFO *check_match(INFO **info, char service_type, int *info_count)
{
    for(int i = 0; i < (*info_count); i ++){
        if(service_type == (*info)->service_type) {
            printf("Found match of service type %c\n",(*info)->service_type);
            return *info;
        }
        info++;
    }
    info = info - (*info_count);
    return NULL;
}

void remove_entry(INFO **info, int client_id, int *info_count)
{
    int found_index = 0;
    for(int i = 0; i < (*info_count); i ++) {
        if(client_id == (*info)->client_id) {
            free(*info);
            found_index = i;
            break;
        }
        info ++;
    }
    if(found_index > 0) {
        for(int i = found_index; i < (*info_count); i++) {
            (*info) = *(info + 1);
            info++;
        }
    }
    (*info_count)--;
    info = info - (*info_count);
    printf("Removed analyst from list\n");
    SSL_write((*info)->a_ssl, NULL, 0);
}
*/
