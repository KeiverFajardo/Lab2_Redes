/*-----------------------------------------------------------------------------
 * file: sr_pwospf.c
 *
 * Descripción:
 * Este archivo contiene las funciones necesarias para el manejo de los paquetes
 * OSPF.
 *
 *---------------------------------------------------------------------------*/

#include "sr_pwospf.h"
#include "sr_router.h"

#include <stdio.h>
#include <unistd.h>
#include <assert.h>
#include <malloc.h>

#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <sys/time.h>
#include <stdint.h>

#include "sr_utils.h"
#include "sr_protocol.h"
#include "pwospf_protocol.h"
#include "sr_rt.h"
#include "pwospf_neighbors.h"
#include "pwospf_topology.h"
#include "dijkstra.h"

/*pthread_t hello_thread;*/
pthread_t g_hello_packet_thread;
pthread_t g_all_lsu_thread;
pthread_t g_lsu_thread;
pthread_t g_neighbors_thread;
pthread_t g_topology_entries_thread;
pthread_t g_rx_lsu_thread;
pthread_t g_dijkstra_thread;

pthread_mutex_t g_dijkstra_mutex = PTHREAD_MUTEX_INITIALIZER;

struct in_addr g_router_id;
uint8_t g_ospf_multicast_mac[ETHER_ADDR_LEN];
struct ospfv2_neighbor* g_neighbors;
struct pwospf_topology_entry* g_topology;
uint16_t g_sequence_num;

/* -- Declaración de hilo principal de la función del subsistema pwospf --- */
static void* pwospf_run_thread(void* arg);

/*---------------------------------------------------------------------
 * Method: pwospf_init(..)
 *
 * Configura las estructuras de datos internas para el subsistema pwospf
 * y crea un nuevo hilo para el subsistema pwospf.
 *
 * Se puede asumir que las interfaces han sido creadas e inicializadas
 * en este punto.
 *---------------------------------------------------------------------*/

int pwospf_init(struct sr_instance* sr)
{
    assert(sr);

    sr->ospf_subsys = (struct pwospf_subsys*)malloc(sizeof(struct
                                                    pwospf_subsys));

    assert(sr->ospf_subsys);
    pthread_mutex_init(&(sr->ospf_subsys->lock), 0);

    g_router_id.s_addr = 0;

    /* Defino la MAC de multicast a usar para los paquetes HELLO */
    g_ospf_multicast_mac[0] = 0x01;
    g_ospf_multicast_mac[1] = 0x00;
    g_ospf_multicast_mac[2] = 0x5e;
    g_ospf_multicast_mac[3] = 0x00;
    g_ospf_multicast_mac[4] = 0x00;
    g_ospf_multicast_mac[5] = 0x05;

    g_neighbors = NULL;

    g_sequence_num = 0;


    struct in_addr zero;
    zero.s_addr = 0;
    g_neighbors = create_ospfv2_neighbor(zero);
    g_topology = create_ospfv2_topology_entry(zero, zero, zero, zero, zero, 0);

    /* -- start thread subsystem -- */
    if( pthread_create(&sr->ospf_subsys->thread, 0, pwospf_run_thread, sr)) { 
        perror("pthread_create");
        assert(0);
    }

    return 0; /* success */
} /* -- pwospf_init -- */


/*---------------------------------------------------------------------
 * Method: pwospf_lock
 *
 * Lock mutex associated with pwospf_subsys
 *
 *---------------------------------------------------------------------*/

void pwospf_lock(struct pwospf_subsys* subsys)
{
    if ( pthread_mutex_lock(&subsys->lock) )
    { assert(0); }
}

/*---------------------------------------------------------------------
 * Method: pwospf_unlock
 *
 * Unlock mutex associated with pwospf subsystem
 *
 *---------------------------------------------------------------------*/

void pwospf_unlock(struct pwospf_subsys* subsys)
{
    if ( pthread_mutex_unlock(&subsys->lock) )
    { assert(0); }
} 

/*---------------------------------------------------------------------
 * Method: pwospf_run_thread
 *
 * Hilo principal del subsistema pwospf.
 *
 *---------------------------------------------------------------------*/

static
void* pwospf_run_thread(void* arg)
{
    sleep(5);

    struct sr_instance* sr = (struct sr_instance*)arg;

    /* Set the ID of the router */
    while(g_router_id.s_addr == 0)
    {
        struct sr_if* int_temp = sr->if_list;
        while(int_temp != NULL)
        {
            if (int_temp->ip > g_router_id.s_addr)
            {
                g_router_id.s_addr = int_temp->ip;
            }

            int_temp = int_temp->next;
        }
    }
    Debug("\n\nPWOSPF: Selecting the highest IP address on a router as the router ID\n");
    Debug("-> PWOSPF: The router ID is [%s]\n", inet_ntoa(g_router_id));


    Debug("\nPWOSPF: Detecting the router interfaces and adding their networks to the routing table\n");
    struct sr_if* int_temp = sr->if_list;
    while(int_temp != NULL)
    {
        struct in_addr ip;
        ip.s_addr = int_temp->ip;
        struct in_addr gw;
        gw.s_addr = 0x00000000;
        struct in_addr mask;
        mask.s_addr =  int_temp->mask;
        struct in_addr network;
        network.s_addr = ip.s_addr & mask.s_addr;

        if (check_route(sr, network) == 0)
        {
            Debug("-> PWOSPF: Adding the directly connected network [%s, ", inet_ntoa(network));
            Debug("%s] to the routing table\n", inet_ntoa(mask));
            sr_add_rt_entry(sr, network, gw, mask, int_temp->name, 1);
        }
        int_temp = int_temp->next;
    }
    
    Debug("\n-> PWOSPF: Printing the forwarding table\n");
    sr_print_routing_table(sr);


    pthread_create(&g_hello_packet_thread, NULL, send_hellos, sr);
    pthread_create(&g_all_lsu_thread, NULL, send_all_lsu, sr);
     pthread_create(&g_neighbors_thread, NULL, check_neighbors_life, sr);
    pthread_create(&g_topology_entries_thread, NULL, check_topology_entries_age, sr);

    return NULL;
} /* -- run_ospf_thread -- */

/***********************************************************************************
 * Métodos para el manejo de los paquetes HELLO y LSU
 * SU CÓDIGO DEBERÍA IR AQUÍ
 * *********************************************************************************/

/*---------------------------------------------------------------------
 * Method: check_neighbors_life
 *
 * Chequea si los vecinos están vivos
 *
 *---------------------------------------------------------------------*/

void* check_neighbors_life(void* arg)
{
    /* 
    Cada 1 segundo, chequea la lista de vecinos. 
    Si hay un cambio, se debe ajustar el neighbor id en la interfaz.
    */
    printf("----------------\n");
    printf("COMIENZO FUNC. CHECK NEIGHBORS LIFE\n");
    printf("----------------\n");

    struct sr_instance* sr = (struct sr_instance*)arg;

    while(1){
        sleep(1);
        check_neighbors_alive(g_neighbors);
    };
    
    printf("----------------\n");
    printf("FIN FUNC. CHECK NEIGHBORS LIFE\n");
    printf("----------------\n");
    return NULL;
} /* -- check_neighbors_life -- */


/*---------------------------------------------------------------------
 * Method: check_topology_entries_age
 *
 * Check if the topology entries are alive 
 * and if they are not, remove them from the topology table
 *
 *---------------------------------------------------------------------*/

void* check_topology_entries_age(void* arg)
{
    printf("----------------\n");
    printf("COMIENZO FUNC. CHECK TOPOLOGY ENTRIES AGE\n");
    printf("----------------\n");
    struct sr_instance* sr = (struct sr_instance*)arg;

    /* Cada 1 segundo, chequea el tiempo de vida de cada entrada de la topologia.
    Si hay un cambio en la topología, se llama a la función de Dijkstra en un nuevo hilo.
    Se sugiere también imprimir la topología resultado del chequeo.*/

    while(1){
        sleep(1);
        if(check_topology_age(g_topology) == 1){
            dijkstra_param_t* dijkstraParam = ((dijkstra_param_t*)(malloc(sizeof(dijkstra_param_t))));
            dijkstraParam->sr = sr;
            dijkstraParam->topology = g_topology;
            dijkstraParam->rid = g_router_id; 

            print_topolgy_table(g_topology);

            pthread_create(&g_dijkstra_thread,NULL,run_dijkstra,dijkstraParam);
        }
    }
    
    printf("----------------\n");
    printf("FIN FUNC. CHECK TOPOLOGY ENTRIES AGE\n");
    printf("----------------\n");
    return NULL;
} /* -- check_topology_entries_age -- */


/*---------------------------------------------------------------------
 * Method: send_hellos
 *
 * Para cada interfaz y cada helloint segundos, construye mensaje 
 * HELLO y crea un hilo con la función para enviar el mensaje.
 *
 *---------------------------------------------------------------------*/

void* send_hellos(void* arg)
{
    printf("----------------\n");
    printf("COMIENZO FUNC. SEND HELLOSSSS\n");
    printf("----------------\n");
    struct sr_instance* sr = (struct sr_instance*)arg;

    /* While true */
    while(1)
    {
        /* Se ejecuta cada 1 segundo */
        usleep(1000000);

        /* Bloqueo para evitar mezclar el envío de HELLOs y LSUs */
        pwospf_lock(sr->ospf_subsys);

        /* Chequeo todas las interfaces para enviar el paquete HELLO */
        /* Cada interfaz matiene un contador en segundos para los HELLO*/
        struct sr_if* ifaces = sr->if_list;
        while (ifaces != NULL){

            if(ifaces->helloint > 0){
                ifaces->helloint--;
            }
            else{
                struct powspf_hello_lsu_param* hParam = ((powspf_hello_lsu_param_t*)(malloc(sizeof(powspf_hello_lsu_param_t))));
                hParam->sr = sr;
                hParam->interface = ifaces;
                pthread_create(&g_hello_packet_thread,NULL,send_hello_packet,hParam);
                /* Reiniciar el contador de segundos para HELLO */
                ifaces->helloint = OSPF_DEFAULT_HELLOINT;
            }
            ifaces = ifaces->next;
        }

        /* Desbloqueo */
        pwospf_unlock(sr->ospf_subsys);
    };

    printf("----------------\n");
    printf("FIN FUNC. SEND HELLOSSSS\n");
    printf("----------------\n");
    return NULL;
} /* -- send_hellos -- */


/*---------------------------------------------------------------------
 * Method: send_hello_packet
 *
 * Recibe un mensaje HELLO, agrega cabezales y lo envía por la interfaz
 * correspondiente.
 *
 *---------------------------------------------------------------------*/

void* send_hello_packet(void* arg)
{
    printf("----------------\n");
    printf("COMIENZO FUNC. SEND HELLO\n");
    printf("----------------\n");

    powspf_hello_lsu_param_t* hello_param = ((powspf_hello_lsu_param_t*)(arg));

    Debug("\n\nPWOSPF: Constructing HELLO packet for interface %s: \n", hello_param->interface->name);
    
    sr_ethernet_hdr_t* ethHeader = ((sr_ethernet_hdr_t*)(malloc(sizeof(sr_ethernet_hdr_t))));
    
    /* Seteo la dirección MAC de multicast para la trama a enviar */
    int j;
    for (j = 0; j <ETHER_ADDR_LEN; j++){
        ethHeader->ether_dhost[j] = g_ospf_multicast_mac[j];
    }
    
    /* Seteo la dirección MAC origen con la dirección de mi interfaz de salida */
    int i;
    for(i = 0; i<ETHER_ADDR_LEN; i++){
        ethHeader->ether_shost[i] = ((uint8_t)hello_param->interface->addr[i]);
    }

    /* Seteo el ether_type en el cabezal Ethernet */
    ethHeader->ether_type = htons(ethertype_ip);

    /* Inicializo cabezal IP */
    struct timeval tv;
    gettimeofday(&tv, NULL); /*Obtiene la hora actual en segundos y microsegundos*/
    int id = (int)((tv.tv_sec * 1000 + tv.tv_usec / 1000) % 2147483647);

    sr_ip_hdr_t* ipHeader = ((sr_ip_hdr_t*)(malloc(sizeof(sr_ip_hdr_t))));

    ipHeader->ip_v = 4;  /* Versión IP (IPv4) */
    ipHeader->ip_hl = 5;  /* Longitud del encabezado IP */ /*OJOOOOOOOOO Puede SER el valor 5*/
    ipHeader->ip_tos = 0;  /* Tipo de servicio */
    ipHeader->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(ospfv2_hdr_t) + sizeof(ospfv2_hello_hdr_t));  /* Longitud total del paquete IP */
    ipHeader->ip_id = id; 
    ipHeader->ip_off = 0;  /* Bandera "Don't Fragment" */
    ipHeader->ip_ttl = 64;  /* Time to Live */
    /* Seteo el protocolo en el cabezal IP para ser el de OSPF (89) */
    ipHeader->ip_p = ip_protocol_ospfv2;
    /* Seteo IP origen con la IP de mi interfaz de salida */
    ipHeader->ip_src = hello_param->interface->ip;
    /* Seteo IP destino con la IP de Multicast dada: OSPF_AllSPFRouters  */
    ipHeader->ip_dst = htonl(OSPF_AllSPFRouters);
    /* Calculo y seteo el checksum IP*/
    ipHeader->ip_sum = 0;
    ipHeader->ip_sum =  ip_cksum(ipHeader, sizeof(sr_ip_hdr_t));

    /* Inicializo cabezal de PWOSPF con version 2 y tipo HELLO */
    ospfv2_hdr_t* ospfHeader = ((ospfv2_hdr_t*)(malloc(sizeof(ospfv2_hdr_t))));
    ospfHeader->version = OSPF_V2;
    ospfHeader->type = OSPF_TYPE_HELLO;
    /* Seteo el Router ID con mi ID*/
    ospfHeader->rid = g_router_id.s_addr;
    /* Seteo el Area ID en 0 */
    ospfHeader->aid = 0;
    /* Seteo el Authentication Type y Authentication Data en 0*/
    ospfHeader->autype = 0;
    ospfHeader->audata = 0;
    
    
    ospfHeader->len = htons(sizeof(ospfv2_hdr_t) + sizeof(ospfv2_hello_hdr_t));
    ospfHeader->csum = 0;

    ospfv2_hello_hdr_t* ospfHelloHeader = ((ospfv2_hello_hdr_t*)(malloc(sizeof(ospfv2_hello_hdr_t))));

    /* Seteo máscara con la máscara de mi interfaz de salida */
    ospfHelloHeader->nmask = hello_param->interface->mask;
    /* Seteo Hello Interval con OSPF_DEFAULT_HELLOINT */
    ospfHelloHeader->helloint = htons(OSPF_DEFAULT_HELLOINT);
    /* Seteo Padding en 0*/
    ospfHelloHeader->padding = 0;

    
    /* Creo el paquete a transmitir */
    uint8_t *packet = ((uint8_t*)(malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(ospfv2_hdr_t) + sizeof(ospfv2_hello_hdr_t))));
    memcpy(packet, ethHeader, sizeof(sr_ethernet_hdr_t));
    memcpy(packet + sizeof(sr_ethernet_hdr_t), ipHeader, sizeof(sr_ip_hdr_t));
    memcpy(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t), ospfHeader, sizeof(ospfv2_hdr_t));
    memcpy(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(ospfv2_hdr_t), ospfHelloHeader, sizeof(ospfv2_hello_hdr_t));

    ((ospfv2_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)))->csum = ospfv2_cksum(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) , sizeof(ospfv2_hdr_t) + sizeof(ospfv2_hello_hdr_t));
    printf("El valor del cksum A ENVIAR es: %d\n", ((ospfv2_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)))->csum);
    sr_send_packet(hello_param->sr, packet, sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(ospfv2_hdr_t) + sizeof(ospfv2_hello_hdr_t), hello_param->interface->name);

    Debug("-> PWOSPF: Sending HELLO Packet of length = %lu, out of the interface: %s\n", sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(ospfv2_hdr_t) + sizeof(ospfv2_hello_hdr_t), hello_param->interface->name);
    Debug("      [Router ID = %s]\n", inet_ntoa(g_router_id));
    /* Debug("      [Router IP = %s]\n", inet_ntoa(ip));
    Debug("      [Network Mask = %s]\n", inet_ntoa(mask)); */

    printf("----------------\n");
    printf("FIN DE FUNC. SEND HELLO\n");
    printf("----------------\n");

    return NULL;
} /* -- send_hello_packet -- */

/*---------------------------------------------------------------------
 * Method: send_all_lsu
 *
 * Construye y envía LSUs cada 30 segundos
 *
 *---------------------------------------------------------------------*/

void* send_all_lsu(void* arg)
{
    printf("----------------\n");
    printf("COMIENZO FUNC. SEND ALL LSU\n");
    printf("----------------\n");

    struct sr_instance* sr = (struct sr_instance*)arg;
    
    /* while true*/
    while(1)
    {
        /* Se ejecuta cada OSPF_DEFAULT_LSUINT segundos */
        usleep(OSPF_DEFAULT_LSUINT * 1000000);

        /* Bloqueo para evitar mezclar el envío de HELLOs y LSUs */
        pwospf_lock(sr->ospf_subsys);

        /*Creo el paquete LSU*/
        int cantRoutes = count_routes(sr);
        
        sr_ethernet_hdr_t* ethHeader = ((sr_ethernet_hdr_t*)(malloc(sizeof(sr_ethernet_hdr_t))));
    
        /*Seteando header ethernet*/
        ethHeader->ether_type = htons(ethertype_ip);

        /*Direcciones mac src y dst la dejo para despues dependiendo de la interfaz*/
        
        /*Seteando header ip*/
        sr_ip_hdr_t* ipHeader = ((sr_ip_hdr_t*)(malloc(sizeof(sr_ip_hdr_t)))); /*OJOOOOO estaba mal el 'malloc(sizeof(sr_ethernet_hdr_t)'*/
        
        struct timeval tv;
        gettimeofday(&tv, NULL); /* Obtiene la hora actual en segundos y microsegundos*/
        int id = (int)((tv.tv_sec * 1000 + tv.tv_usec / 1000) % 2147483647);

        ipHeader->ip_id =id;
        ipHeader->ip_v = 4;  /* Versión IP (IPv4) */
        ipHeader->ip_hl = 5;  /* Longitud del encabezado IP */ /* OJOOOOOOOOOO PODRIA SER EL VALOR 5*/
        ipHeader->ip_tos = 0;  /* Tipo de servicio */
        ipHeader->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(ospfv2_hdr_t) + sizeof(ospfv2_lsu_hdr_t) + (sizeof(ospfv2_lsa_t) * cantRoutes));  /* Longitud total del paquete IP */
        ipHeader->ip_off = 0;  /* Bandera "Don't Fragment" */
        ipHeader->ip_ttl = 64;  /* Time to Live */
        ipHeader->ip_p = ip_protocol_ospfv2;  /* Protocolo ICMP */
        ipHeader->ip_sum = 0;

        /*Seteando header OSPFv2*/
        ospfv2_hdr_t* ospfHeader = ((ospfv2_hdr_t*)(malloc(sizeof(ospfv2_hdr_t))));
    
        ospfHeader->version = OSPF_V2;
        ospfHeader->type = OSPF_TYPE_LSU;
        ospfHeader->len = htons(sizeof(ospfv2_hdr_t) + sizeof(ospfv2_lsu_hdr_t) + (sizeof(ospfv2_lsa_t) * cantRoutes));
        ospfHeader->rid = g_router_id.s_addr;
        ospfHeader->aid = 0;
        ospfHeader->csum = 0;
        ospfHeader->autype = 0;
        ospfHeader->audata = 0;

        /*Seteando header lsu*/
        ospfv2_lsu_hdr_t* lsuHeader = ((ospfv2_lsu_hdr_t*)(malloc(sizeof(ospfv2_lsu_hdr_t))));
        ospfv2_lsa_t* lsaHeader = ((ospfv2_lsa_t*)(malloc(sizeof(ospfv2_lsa_t))));

        g_sequence_num++;
        lsuHeader->seq = htons(g_sequence_num);
        lsuHeader->unused = 0;
        lsuHeader->ttl = 64;
        lsuHeader->num_adv = htonl(cantRoutes);

        uint8_t* packet = ((uint8_t*)(malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(ospfv2_hdr_t) + sizeof(ospfv2_lsu_hdr_t) + (sizeof(ospfv2_lsa_t) * cantRoutes))));


        /* Recorro todas las interfaces para enviar el paquete LSU */
        struct sr_if* ifaces = sr->if_list;
        int cantLSA = 0;
        while(ifaces != NULL){
            
            /* Si la interfaz tiene un vecino, envío un LSU */
            if(ifaces->neighbor_ip != 0){
                /* Ehternet Source address OJOOOOOOOOOOOOOOOOOO FALTABA EL ETHER_SHOST*/
                int i;
                for (i = 0; i < ETHER_ADDR_LEN; i++)
                {
                    ethHeader->ether_shost[i] = ((uint8_t)(ifaces->addr[i]));
                }

                ipHeader->ip_src = ifaces->ip;
                ipHeader->ip_dst = ifaces->neighbor_ip;
                /* OJOOOOOOOOO faltaba el checksum */
                ipHeader->ip_sum = ip_cksum(ipHeader, sizeof(sr_ip_hdr_t));

                struct sr_rt* table_entry = sr->routing_table;
                while (table_entry != NULL);
                {
                    /* Solo envío entradas directamente conectadas y agreagadas a mano*/
                    if (table_entry->admin_dst <= 1)
                    {
                        /* Creo LSA con subnet, mask y routerID (id del vecino de la interfaz)*/
                        lsaHeader->mask = table_entry->mask.s_addr;
                        lsaHeader->subnet = table_entry->dest.s_addr;
                        lsaHeader->rid = sr_get_interface(sr,table_entry->interface)->neighbor_id;
                        /*OJOOOOOOOO ESTABA MAL LA SIGUIENTE LINEA*/
                        /*memcpy(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(ospfv2_hdr_t) + sizeof(ospfv2_lsu_hdr_t),lsuHeader,sizeof(ospfv2_lsa_t)*cantLSA);*/
                        memcpy(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(ospfv2_hdr_t) + sizeof(ospfv2_lsu_hdr_t) + (sizeof(ospfv2_lsa_t) * cantLSA), lsaHeader, sizeof(ospfv2_lsa_t));
                        /*contador para añadir mas LSA al paquete*/
                        cantLSA++;
                    }
                    table_entry = table_entry->next;
                }

                /* OJOOOOOOO arregle esta linea Calculo el checksum del paquete LSU */
                ospfHeader->csum = ospfv2_cksum(ospfHeader, sizeof(ospfv2_hdr_t) + sizeof(ospfv2_lsu_hdr_t) + (sizeof(ospfv2_lsa_t) * cantRoutes));  /*OJOOOOOOOOOOOOOOOOOO Cambiar cantLSA por cantRoutes si corresponde*/

                /* Me falta la MAC para poder enviar el paquete, la busco en la cache ARP*/
                struct sr_arpentry *arpEntry = sr_arpcache_lookup(&(sr->cache), ifaces->neighbor_ip);
                int packet_len = (sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(ospfv2_hdr_t) + sizeof(ospfv2_lsu_hdr_t) + (sizeof(ospfv2_lsa_t) * cantLSA)); /*OJOOOOO CORREGI QUE NO SUMABA BIEN*/

                /* Envío el paquete si obtuve la MAC o lo guardo en la cola para cuando tenga la MAC*/
                
                if(arpEntry){
                    int i;
                    for (i = 0; i < ETHER_ADDR_LEN; i++)
                    {
                        ethHeader->ether_dhost[i] = arpEntry->mac[i]; /*OJOOOOOOO*/
                    }
                    memcpy(packet, ethHeader, sizeof(sr_ethernet_hdr_t));
                    memcpy(packet + sizeof(sr_ethernet_hdr_t), ipHeader, sizeof(sr_ip_hdr_t));
                    memcpy(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t), ospfHeader, sizeof(ospfv2_hdr_t));
                    memcpy(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(ospfv2_hdr_t), lsuHeader, sizeof(ospfv2_lsu_hdr_t));
                    sr_send_packet(sr, packet, packet_len , ifaces->name);
                }
                else{
                    memcpy(packet, ethHeader, sizeof(sr_ethernet_hdr_t));
                    memcpy(packet + sizeof(sr_ethernet_hdr_t), ipHeader, sizeof(sr_ip_hdr_t));
                    memcpy(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t), ospfHeader, sizeof(ospfv2_hdr_t));
                    memcpy(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(ospfv2_hdr_t), lsuHeader, sizeof(ospfv2_lsu_hdr_t));
                    struct sr_arpreq *arpReq = sr_arpcache_queuereq(&(sr->cache), ipHeader->ip_dst, packet, packet_len, ifaces->name);
                    if(arpReq != NULL){
                        handle_arpreq(sr,arpReq);
                    }
                }
            }
            ifaces = ifaces->next;
        }

        /* OJOOOOOOO REVISAR CAPAZ FALTA LIBERAR LA MEMORIA DEL PAQUETE */
        /* 
            free(packet);
            free(lsaHeader);
            free(lsuHeader);
            free(ospfHeader);
            free(ipHeader);
            free(ospfHeader); 
        */

        /* Desbloqueo */
        pwospf_unlock(sr->ospf_subsys);
    };

    printf("----------------\n");
    printf("FIN FUNC. SEND ALL LSU\n");
    printf("----------------\n");
    return NULL;
} /* -- send_all_lsu -- */

/*---------------------------------------------------------------------
 * Method: send_lsu
 *
 * Construye y envía paquetes LSU a través de una interfaz específica
 *
 *---------------------------------------------------------------------*/

void* send_lsu(void* arg)
{
    struct powspf_hello_lsu_param* lsu_param = ((struct powspf_hello_lsu_param*)(arg));
    
    /* Construyo el LSU */
    Debug("\n\nPWOSPF: Constructing LSU packet\n");

    /* Me falta la MAC para poder enviar el paquete, la busco en la cache ARP*/
    /* Envío el paquete si obtuve la MAC o lo guardo en la cola para cuando tenga la MAC*/
   
   /* Libero memoria */


    /* Solo envío LSUs si del otro lado hay un router*/
    if (lsu_param->interface->neighbor_ip == 0)
    {
        return NULL;
    }

    /* Constructing LSU */
    Debug("\n\nPWOSPF: Constructing LSU packet\n");
    /* Inicializo cabezal Ethernet */
    /* Dirección MAC destino la dejo para el final ya que hay que hacer ARP */
    sr_ethernet_hdr_t* tx_e_hdr = ((sr_ethernet_hdr_t*)(malloc(sizeof(sr_ethernet_hdr_t))));

    tx_e_hdr->ether_type = htons(ethertype_ip);
    memcpy(tx_e_hdr->ether_shost,lsu_param->interface->addr,ETHER_ADDR_LEN);        

    int routes_num = count_routes(lsu_param->sr);

    /* Inicializo cabezal IP*/
    /* La IP destino es la del vecino contectado a mi interfaz*/
    sr_ip_hdr_t* tx_ip_hdr = ((sr_ip_hdr_t*)(malloc(sizeof(sr_ip_hdr_t))));

    tx_ip_hdr->ip_v = 4;
    tx_ip_hdr->ip_hl = 5;
    tx_ip_hdr->ip_tos = 0;
    tx_ip_hdr->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(ospfv2_hdr_t) + sizeof(ospfv2_lsu_hdr_t) + (sizeof(ospfv2_lsa_t) * routes_num));
    struct timeval tv;
    gettimeofday(&tv, NULL);
    srand(tv.tv_sec * tv.tv_usec);
    tx_ip_hdr->ip_id = rand();
    tx_ip_hdr->ip_off = 0;
    tx_ip_hdr->ip_ttl = 64;
    tx_ip_hdr->ip_p = ip_protocol_ospfv2; 
    tx_ip_hdr->ip_sum = 0;
    tx_ip_hdr->ip_src = lsu_param->interface->ip;
    tx_ip_hdr->ip_dst = lsu_param->interface->neighbor_ip;
    tx_ip_hdr->ip_sum = ip_cksum((sr_ip_hdr_t *)tx_ip_hdr, sizeof(sr_ip_hdr_t));


    /* Inicializo cabezal de OSPF*/
    /* Seteo el número de secuencia y avanzo*/
    /* Seteo el TTL en 64 y el resto de los campos del cabezal de LSU */
    /* Seteo el número de anuncios con la cantidad de rutas a enviar. Uso función count_routes */
    ospfv2_hdr_t* tx_ospf_hdr = ((ospfv2_hdr_t*)(malloc(sizeof(ospfv2_hdr_t))));

    tx_ospf_hdr->version = OSPF_V2;
    tx_ospf_hdr->type = OSPF_TYPE_LSU;
    tx_ospf_hdr->len = htons(sizeof(ospfv2_hdr_t) + sizeof(ospfv2_lsu_hdr_t) + (sizeof(ospfv2_lsa_t) * routes_num));
    tx_ospf_hdr->rid = g_router_id.s_addr;    
    tx_ospf_hdr->aid = htonl(171); 
    tx_ospf_hdr->csum = 0;
    tx_ospf_hdr->autype = 0;
    tx_ospf_hdr->audata = 0;

    ospfv2_lsu_hdr_t* tx_ospf_lsu_hdr = ((ospfv2_lsu_hdr_t*)(malloc(sizeof(ospfv2_lsu_hdr_t))));
    g_sequence_num++;
    tx_ospf_lsu_hdr->seq = htons(g_sequence_num);
    tx_ospf_lsu_hdr->unused = 0;
    tx_ospf_lsu_hdr->ttl = 64;
    tx_ospf_lsu_hdr->num_adv = htonl(routes_num);

    ospfv2_lsa_t* tx_ospf_lsa = ((ospfv2_lsa_t*)(malloc(sizeof(ospfv2_lsa_t))));

    int packet_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(ospfv2_hdr_t) + sizeof(ospfv2_lsu_hdr_t) + (sizeof(ospfv2_lsa_t) * routes_num);
    uint8_t* tx_packet;

    
    
    /* Creo el paquete y seteo todos los cabezales del paquete a transmitir */
    tx_packet = ((uint8_t*)(malloc(packet_len)));

    memcpy(tx_packet, tx_e_hdr, sizeof(sr_ethernet_hdr_t));
    memcpy(tx_packet + sizeof(sr_ethernet_hdr_t), tx_ip_hdr, sizeof(sr_ip_hdr_t));
    memcpy(tx_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t), tx_ospf_hdr, sizeof(ospfv2_hdr_t));
    memcpy(tx_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(ospfv2_hdr_t), tx_ospf_lsu_hdr, sizeof(ospfv2_lsu_hdr_t));

    int k = 0;
    struct sr_rt* entry = lsu_param->sr->routing_table;
    while (entry != NULL)
    {
        /* Creo cada LSA iterando en las enttadas de la tabla */
        /* Solo envío entradas directamente conectadas y agreagadas a mano*/
        /* Creo LSA con subnet, mask y routerID (id del vecino de la interfaz)*/
        if (entry->admin_dst <= 1)
        {
            tx_ospf_lsa->subnet = entry->dest.s_addr;
            tx_ospf_lsa->mask = entry->mask.s_addr;
            tx_ospf_lsa->rid = sr_get_interface(lsu_param->sr, entry->interface)->neighbor_id;
            memcpy(tx_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(ospfv2_hdr_t) + sizeof(ospfv2_lsu_hdr_t) + (sizeof(ospfv2_lsa_t) * k),
                tx_ospf_lsa, sizeof(ospfv2_lsa_t));
            k++;
        }
        entry = entry->next;
    }

    /* Calculo el checksum del paquete LSU */
    ((ospfv2_hdr_t*)(tx_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)))->csum =
        ospfv2_cksum((ospfv2_hdr_t*)(tx_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)), 
                     sizeof(ospfv2_hdr_t) + sizeof(ospfv2_lsu_hdr_t) + (sizeof(ospfv2_lsa_t) * routes_num));

     struct sr_arpentry *arpEntry = sr_arpcache_lookup(&(lsu_param->sr->cache), lsu_param->interface->neighbor_ip);
    
    /* Envío el paquete si obtuve la MAC o lo guardo en la cola para cuando tenga la MAC*/
    Debug("-> PWOSPF: Sending LSU Packet of length = %d, out of the interface: %s\n", packet_len, lsu_param->interface->name);
    if(arpEntry){
        memcpy(((sr_ethernet_hdr_t*)tx_packet)->ether_dhost, arpEntry->mac, ETHER_ADDR_LEN);
        sr_send_packet(lsu_param->sr, tx_packet, packet_len , lsu_param->interface->name);
    }
    else{
        struct sr_arpreq *arpReq = sr_arpcache_queuereq(&(lsu_param->sr->cache), tx_ip_hdr->ip_dst, tx_packet, packet_len, lsu_param->interface->name);
        if(arpReq != NULL){
            handle_arpreq(lsu_param->sr,arpReq);
        }
    }


    free(tx_packet);

/*
    Debug("\n\nPWOSPF: Constructing LSU update\n");


    packet_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(ospfv2_hdr_t) + sizeof(ospfv2_lsu_hdr_t) + sizeof(ospfv2_lsa_t);
    tx_packet = ((uint8_t*)(malloc(packet_len)));

    tx_ospf_lsa->subnet = lsu_param->interface->ip & htonl(0xfffffffe);

    tx_ospf_lsa->mask = htonl(0xfffffffe);


    tx_ospf_lsa->rid = sr_get_interface(lsu_param->sr, lsu_param->interface->name)->neighbor_id;


    struct sr_if* temp_int = lsu_param->sr->if_list;
    while (temp_int != NULL)
    {
        if ((strcmp(temp_int->name, lsu_param->interface->name) != 0))
        {
            int i;
            for (i = 0; i < ETHER_ADDR_LEN; i++)
            {
                tx_e_hdr->ether_shost[i] = ((uint8_t)(temp_int->addr[i]));
            }

            

            tx_ip_hdr->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(ospfv2_hdr_t) + sizeof(ospfv2_lsu_hdr_t) + sizeof(ospfv2_lsa_t));


            struct timeval tv;
            gettimeofday(&tv, NULL);
            srand(tv.tv_sec * tv.tv_usec);
            tx_ip_hdr->ip_id = rand();
    
            tx_ip_hdr->ip_sum = 0;


            tx_ip_hdr->ip_src = temp_int->ip;


            tx_ip_hdr->ip_sum = ip_cksum(((uint8_t*)(tx_ip_hdr)), sizeof(sr_ip_hdr_t));


            tx_ospf_hdr->len = htons(sizeof(ospfv2_hdr_t) + sizeof(ospfv2_lsu_hdr_t) + sizeof(ospfv2_lsa_t));


            tx_ospf_hdr->csum = 0;



            g_sequence_num++;
            tx_ospf_lsu_hdr->seq = htons(g_sequence_num);


            tx_ospf_lsu_hdr->num_adv = htonl(1);


            memcpy(tx_packet, tx_e_hdr, sizeof(sr_ethernet_hdr_t));
            memcpy(tx_packet + sizeof(sr_ethernet_hdr_t), tx_ip_hdr, sizeof(sr_ip_hdr_t));
            memcpy(tx_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t), tx_ospf_hdr, sizeof(ospfv2_hdr_t));
            memcpy(tx_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(ospfv2_hdr_t), tx_ospf_lsu_hdr, sizeof(ospfv2_lsu_hdr_t));
            memcpy(tx_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(ospfv2_hdr_t) + sizeof(ospfv2_lsu_hdr_t), tx_ospf_lsa, sizeof(ospfv2_lsa_t));


            ((ospfv2_hdr_t*)(tx_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)))->csum =
                ospfv2_cksum(tx_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t), sizeof(ospfv2_hdr_t) + sizeof(ospfv2_lsu_hdr_t) + sizeof(ospfv2_lsa_t));

            Debug("-> PWOSPF: Sending LSU Update of length = %d, out of the interface: %s\n", packet_len, temp_int->name);
            sr_send_packet(lsu_param->sr, ((uint8_t*)(tx_packet)), packet_len, temp_int->name);
        }

        temp_int = temp_int->next;
    }

    free(tx_packet);
    free(tx_ospf_lsa);
    free(tx_ospf_lsu_hdr);
    free(tx_ospf_hdr);
    free(tx_ip_hdr);
    free(tx_e_hdr);

    
    printf("----------------\n");
    printf("FIN FUNC. SEND LSU\n");
    printf("----------------\n");
*/

    return NULL;
} 
/* -- send_lsu -- */



/*---------------------------------------------------------------------
 * Method: sr_handle_pwospf_hello_packet
 *
 * Gestiona los paquetes HELLO recibidos
 *
 *---------------------------------------------------------------------*/

void sr_handle_pwospf_hello_packet(struct sr_instance* sr, uint8_t* packet, unsigned int length, struct sr_if* rx_if)
{
    printf("----------------\n");
    printf("COMIENZO HANDLE HELLO PACKET\n");
    printf("----------------\n");

    /* Obtengo información del paquete recibido */
    /* Imprimo info del paquete recibido*/

    sr_ip_hdr_t* ipHeader = ((sr_ip_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t)));
    ospfv2_hdr_t* ospfv2Header = ((ospfv2_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)));
    ospfv2_hello_hdr_t* helloHeader = ((ospfv2_hello_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(ospfv2_hdr_t)));


    struct in_addr neighbor_id;
    neighbor_id.s_addr = ospfv2Header->rid;
    struct in_addr net_mask;
    net_mask.s_addr = helloHeader->nmask;

    Debug("-> PWOSPF: Detecting PWOSPF HELLO Packet from:\n");
    Debug("      [Neighbor ID = %s]\n", inet_ntoa(neighbor_id));
    /*Debug("      [Neighbor IP = %s]\n", inet_ntoa(ipHeader->ip_src));*/
    Debug("      [Network Mask = %s]\n", inet_ntoa(net_mask));

    /* Chequeo checksum */
    uint16_t comingCsum = ospfv2Header->csum;
    ospfv2Header->csum = 0;
    uint16_t newCsum = ospfv2_cksum((ospfv2_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)), sizeof(ospfv2_hdr_t) + sizeof(ospfv2_hello_hdr_t));
    if (comingCsum != newCsum)
    {
        Debug("-> PWOSPF: HELLO Packet dropped, invalid checksum\n");
        return;
    }
    ospfv2Header->csum = comingCsum;
    
    /* Chequeo de la máscara de red */
    if (helloHeader->nmask != rx_if->mask)
    {
        Debug("-> PWOSPF: HELLO Packet dropped, invalid hello network mask\n");
        return;
    }

    /* Chequeo del intervalo de HELLO */
    if (helloHeader->helloint != htons(OSPF_DEFAULT_HELLOINT)) /*OJOOOOO agregue el htons*/
    {
        Debug("-> PWOSPF: HELLO Packet dropped, invalid hello interval\n");
        return;
    }

    /*OJOOOOOOOOOOOOOOOOOOOOOOO CON REVISAR ESTE METODO QUE HAGA LO QUE DICE ACA*/
    /* Seteo el vecino en la interfaz por donde llegó y actualizo la lista de vecinos */

    /* Si es un nuevo vecino, debo enviar LSUs por todas mis interfaces*/
        /* Recorro todas las interfaces para enviar el paquete LSU */
        /* Si la interfaz tiene un vecino, envío un LSU */
        
    int new_ngbor = 0;
    if(rx_if->neighbor_id != ospfv2Header->rid){
        rx_if->neighbor_id = ospfv2Header->rid;
        new_ngbor = 1;
    }
    rx_if->neighbor_ip = ipHeader->ip_src;

    refresh_neighbors_alive(g_neighbors,neighbor_id);

    if(new_ngbor == 1){
        powspf_hello_lsu_param_t* paramLsu = ((powspf_hello_lsu_param_t*)(malloc(sizeof(powspf_hello_lsu_param_t))));
        paramLsu->sr = sr;
        paramLsu->interface = rx_if;
        pthread_create(&g_lsu_thread, NULL, send_lsu, paramLsu);
    }

    printf("----------------\n");
    printf("FIN HANDLE HELLO PACKET\n");
    printf("----------------\n");
} /* -- sr_handle_pwospf_hello_packet -- */


/*---------------------------------------------------------------------
 * Method: sr_handle_pwospf_lsu_packet
 *
 * Gestiona los paquetes LSU recibidos y actualiza la tabla de topología
 * y ejecuta el algoritmo de Dijkstra
 *
 *---------------------------------------------------------------------*/

void* sr_handle_pwospf_lsu_packet(void* arg)
{
    printf("----------------\n");
    printf("COMIENZO HANDLE LSU PACKET\n");
    printf("----------------\n");
    struct powspf_rx_lsu_param* rx_lsu_param = ((struct powspf_rx_lsu_param*)(arg));

    /* Obtengo el vecino que me envió el LSU*/
    /* Imprimo info del paquete recibido*/

    sr_ip_hdr_t* ipHeader = ((sr_ip_hdr_t*)(rx_lsu_param->packet + sizeof(sr_ethernet_hdr_t)));
    ospfv2_hdr_t* ospfv2Header = ((ospfv2_hdr_t*)(rx_lsu_param->packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)));
    ospfv2_lsu_hdr_t* lsuHeader = ((ospfv2_lsu_hdr_t*)(rx_lsu_param->packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(ospfv2_hdr_t)));

    struct in_addr neighbor_id;
    neighbor_id.s_addr = ospfv2Header->rid;
    Debug("-> PWOSPF: Detecting LSU Packet from [Neighbor ID = %s]\n", inet_ntoa(neighbor_id));

    /* Chequeo checksum */
    uint16_t comingCsum = ospfv2Header->csum;
    ospfv2Header->csum = 0;
    uint16_t newCsum = ospfv2_cksum((ospfv2_hdr_t *)(rx_lsu_param->packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)), htons(ospfv2Header->len));
    if (comingCsum != newCsum)
    {
        Debug("-> PWOSPF: LSU Packet dropped, invalid checksum\n");
        return NULL;
    }
    ospfv2Header->csum = comingCsum;

    /* Obtengo el Router ID del router originario del LSU y chequeo si no es mío*/
    /*Chequeo router id*/
    if (ospfv2Header->rid == g_router_id.s_addr)
    {
        Debug("-> PWOSPF: LSU Packet dropped, originated by this router\n");
        return NULL;        
    }

    /* Obtengo el número de secuencia y uso check_sequence_number para ver si ya lo recibí desde ese vecino
    uint16_t seqNumber = lsuHeader->seq;
    if(check_sequence_number(g_topology, g_router_id, seqNumber)){
        Debug("-> PWOSPF: LSU Packet dropped, repeated sequence number\n");
        return NULL;
    }*/


    /* Itero en los LSA que forman parte del LSU. Para cada uno, actualizo la topología.*/
    /*Debug("-> PWOSPF: Processing LSAs and updating topology table\n");*/        
        /* Obtengo subnet */
        /* Obtengo vecino */
        /* Imprimo info de la entrada de la topología */
        /* LLamo a refresh_topology_entry*/
    int i;
    for (i = 0; i < htonl(lsuHeader->num_adv); i++)
    {
        ospfv2_lsa_t* lsaHeader = ((ospfv2_lsa_t*)(rx_lsu_param->packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(ospfv2_hdr_t) + sizeof(ospfv2_lsu_hdr_t) + (sizeof(ospfv2_lsa_t) * i)));

        struct in_addr net_num;
        net_num.s_addr = lsaHeader->subnet;
        struct in_addr net_mask;
        net_mask.s_addr = lsaHeader->mask;
        struct in_addr neighbor_id;
        neighbor_id.s_addr = lsaHeader->rid;
        
        Debug("      [Subnet = %s]", inet_ntoa(net_num));
        Debug("      [Mask = %s]", inet_ntoa(net_mask));
        Debug("      [Neighbor ID = %s]\n", inet_ntoa(neighbor_id));

        struct in_addr src_addr;
        struct in_addr rid;
        src_addr.s_addr = ipHeader->ip_src;
        rid.s_addr = ospfv2Header->rid;
        refresh_topology_entry(g_topology, rid, net_num, net_mask, neighbor_id, src_addr, htons(lsuHeader->seq));
    }

    /* Imprimo la topología */
    Debug("\n-> PWOSPF: Printing the topology table\n");
    print_topolgy_table(g_topology);


    /* Ejecuto Dijkstra en un nuevo hilo (run_dijkstra)*/
    dijkstra_param_t* dijkstraParam = ((dijkstra_param_t*)(malloc(sizeof(dijkstra_param_t))));
    dijkstraParam->sr = rx_lsu_param->sr;
    dijkstraParam->topology = g_topology;
    pthread_create(&g_dijkstra_thread, NULL, run_dijkstra, dijkstraParam);



    /* Flooding del LSU por todas las interfaces menos por donde me llegó */

    struct sr_if* ifaces = rx_lsu_param->sr->if_list;
    while (ifaces != NULL)
    {
        if ((strcmp(ifaces->name, rx_lsu_param->rx_if->name) != 0))
        {
            /* Seteo MAC de origen */
            int i;
            for (i = 0; i < ETHER_ADDR_LEN; i++)
            {
                ((sr_ethernet_hdr_t*)(rx_lsu_param->packet))->ether_shost[i] = ((uint8_t)(ifaces->addr[i]));
            }

            /* Ajusto paquete IP, origen y checksum*/
            sr_ip_hdr_t* ipHdr = ((sr_ip_hdr_t*)(rx_lsu_param->packet + sizeof(sr_ethernet_hdr_t)));

            struct timeval tv;
            gettimeofday(&tv, NULL); /* Obtiene la hora actual en segundos y microsegundos*/
            int id = (int)((tv.tv_sec * 1000 + tv.tv_usec / 1000) % 2147483647);
            ipHdr->ip_id = id;
            ipHdr->ip_sum = 0;
            ipHdr->ip_src = ifaces->ip; /*OJOOOOOOOOOO aca puede ser que sea con s_addr*/
            ipHdr->ip_sum = ip_cksum(ipHdr, sizeof(sr_ip_hdr_t));

            /* Ajusto cabezal OSPF: checksum y TTL*/           
            lsuHeader->ttl--;

            ospfv2Header->csum = 0;
            ospfv2Header->csum = ospfv2_cksum(ospfv2Header, htons(((ospfv2_hdr_t*)(rx_lsu_param->packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)))->len));

            /* Envío el paquete*/
            sr_send_packet(rx_lsu_param->sr, ((uint8_t*)(rx_lsu_param->packet)), rx_lsu_param->length, ifaces->name);
        }

        ifaces = ifaces->next;
    }

    
    printf("----------------\n");
    printf("FIN HANDLE LSU PACKET\n");
    printf("----------------\n");
    return NULL;
} /* -- sr_handle_pwospf_lsu_packet -- */

/**********************************************************************************
 * SU CÓDIGO DEBERÍA TERMINAR AQUÍ
 * *********************************************************************************/

/*---------------------------------------------------------------------
 * Method: sr_handle_pwospf_packet
 *
 * Gestiona los paquetes PWOSPF
 *
 *---------------------------------------------------------------------*/

void sr_handle_pwospf_packet(struct sr_instance* sr, uint8_t* packet, unsigned int length, struct sr_if* rx_if)
{
    /*Si aún no terminó la inicialización, se descarta el paquete recibido*/
    if (g_router_id.s_addr == 0) {
       return;
    }

    ospfv2_hdr_t* rx_ospfv2_hdr = ((ospfv2_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)));
    powspf_rx_lsu_param_t* rx_lsu_param = ((powspf_rx_lsu_param_t*)(malloc(sizeof(powspf_rx_lsu_param_t))));

    Debug("-> PWOSPF: Detecting PWOSPF Packet\n");
    Debug("      [Type = %d]\n", rx_ospfv2_hdr->type);

    switch(rx_ospfv2_hdr->type)
    {
        case OSPF_TYPE_HELLO:
            sr_handle_pwospf_hello_packet(sr, packet, length, rx_if);
            break;
        case OSPF_TYPE_LSU:
            rx_lsu_param->sr = sr;
            unsigned int i;
            for (i = 0; i < length; i++)
            {
                rx_lsu_param->packet[i] = packet[i];
            }
            rx_lsu_param->length = length;
            rx_lsu_param->rx_if = rx_if;
            pthread_attr_t attr;
            pthread_attr_init(&attr);
            pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
            pthread_t pid;
            pthread_create(&pid, &attr, sr_handle_pwospf_lsu_packet, rx_lsu_param);
            break;
    }
} /* -- sr_handle_pwospf_packet -- */
