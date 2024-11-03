/**********************************************************************
 * file:  sr_router.c
 *
 * Descripción:
 *
 * Este archivo contiene todas las funciones que interactúan directamente
 * con la tabla de enrutamiento, así como el método de entrada principal
 * para el enrutamiento.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

#include <stdint.h>
#include <arpa/inet.h>
#include <netinet/in.h>


/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Inicializa el subsistema de enrutamiento
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    assert(sr);

    /* Inicializa la caché y el hilo de limpieza de la caché */
    sr_arpcache_init(&(sr->cache));

    /* Inicializa los atributos del hilo */
    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    /* Hilo para gestionar el timeout del caché ARP */
    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);

} /* -- sr_init -- */


struct sr_rt* longest_prefix_match(struct sr_instance* sr, uint32_t ip_dst) {
    
    struct sr_rt* rt_entry = sr->routing_table;
    struct sr_rt* best_match = NULL;
    uint32_t longest_match_len = 0;

    while (rt_entry != NULL) {
        /* Aplicar la máscara de red a la dirección de destino y a la dirección de red de la entrada*/
        uint32_t masked_dst = ip_dst & rt_entry->mask.s_addr;
        uint32_t masked_entry = rt_entry->dest.s_addr & rt_entry->mask.s_addr;

        /*Verificar si hay coincidencia*/
        if (masked_dst == masked_entry) {
            /* Contar la longitud del prefijo (bits de coincidencia) de la máscara */
            uint32_t mask = ntohl(rt_entry->mask.s_addr);
            uint32_t match_len = 0;

            while (mask) {
                match_len += (mask & 1);
                mask >>= 1;
            }

            /* Actualizar la mejor coincidencia si esta es más larga */
            if (match_len > longest_match_len) {
                longest_match_len = match_len;
                best_match = rt_entry;
            }
        }

        /* Avanzar a la siguiente entrada de la tabla de enrutamiento */
        rt_entry = rt_entry->next;
    }

    /* Si se encontró la mejor coincidencia, devolver la entrada de la tabla de enrutamiento */
    printf("**********BEST MATCH*********\n");
    sr_print_routing_entry(best_match);
    return best_match;
}





/*-----------------------------------------------------------------------------------------------------------------*/
/*-----------------------------------------------------------------------------------------------------------------*/
/*-------------------------------------SEND ICMP ERROR------------------------------------------------------------*/
/*-----------------------------------------------------------------------------------------------------------------*/
/*-----------------------------------------------------------------------------------------------------------------*/


/* Envía un paquete ICMP de error */
void sr_send_icmp_error_packet(uint8_t type,
                              uint8_t code,
                              struct sr_instance *sr,
                              uint32_t ipDst,
                              uint8_t *ipPacket)
{
  /* Definir el tamaño del nuevo paquete ICMP (Ethernet + IP + ICMP) */
  int icmpPacketLen = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);

  uint8_t *icmpPacket = malloc(icmpPacketLen);
  if (!icmpPacket) {
    fprintf(stderr, "Error al asignar memoria para el paquete ICMP\n");
    return;
  }
  
  /* Obtener los encabezados Ethernet e IP del paquete original */
  sr_ethernet_hdr_t *origEthHdr = (sr_ethernet_hdr_t *) ipPacket;
  sr_ip_hdr_t *origIpHdr = (sr_ip_hdr_t *) (ipPacket + sizeof(sr_ethernet_hdr_t));

  /* Crear los nuevos encabezados Ethernet, IP e ICMP */
  sr_ethernet_hdr_t *ethHdr = (sr_ethernet_hdr_t *) icmpPacket;
  sr_ip_hdr_t *ipHdr = (sr_ip_hdr_t *) (icmpPacket + sizeof(sr_ethernet_hdr_t));
  /*depende del tipo de mensaje*/
  sr_icmp_t3_hdr_t *icmpHdr = (sr_icmp_t3_hdr_t *) (icmpPacket + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

  /* Destination net unreachable (type 3, code 0) */
  /* Destination host unreachable (type 3, code 1) */
  /* Port unreachable (type 3, code 3) */
  /* Time exceeded (type 11, code 0) */
  
  /* -- Configuración del encabezado ICMP -- */
  icmpHdr->icmp_type = type;  /* Tipo ICMP (por ejemplo, 3 para "Destination Unreachable") */
  icmpHdr->icmp_code = code;  /* Código ICMP (por ejemplo, 1 para "Host Unreachable") */
  icmpHdr->icmp_sum = 0;  /* Inicializar el checksum ICMP */
  icmpHdr->unused = 0;
  icmpHdr->next_mtu = 0;

  /* Copiar los primeros 8 bytes del paquete IP original en el cuerpo del mensaje ICMP */
  memcpy(icmpHdr->data, origIpHdr, ICMP_DATA_SIZE);

  /* Calcular el checksum del paquete ICMP */
  icmpHdr->icmp_sum = icmp3_cksum(icmpHdr, sizeof(sr_icmp_t3_hdr_t));
  
  /* -- Configuración del encabezado IP -- */
  ipHdr->ip_v = 4;  /* Versión IP (IPv4) */
  ipHdr->ip_hl = sizeof(sr_ip_hdr_t) / 4;  /* Longitud del encabezado IP */
  ipHdr->ip_tos = 0;  /* Tipo de servicio */
  ipHdr->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));  /* Longitud total del paquete IP */
  ipHdr->ip_id = 0;  /* ID de fragmentación (0 si no se fragmenta) */
  ipHdr->ip_off = 0;  /* Bandera "Don't Fragment" */
  ipHdr->ip_ttl = 64;  /* Time to Live */
  ipHdr->ip_p = ip_protocol_icmp;  /* Protocolo ICMP */
  ipHdr->ip_src = origIpHdr->ip_dst;  /* Dirección IP de origen (IP del router) OJOOOOOOOOOO */
  ipHdr->ip_dst = ipDst;  /* Dirección IP de destino */
  ipHdr->ip_sum = 0;  /* Inicializar el checksum */
  ipHdr->ip_sum = ip_cksum(ipHdr, sizeof(sr_ip_hdr_t));  /* Calcular el checksum IP */

  /* -- Configuración del encabezado Ethernet -- */
  memcpy(ethHdr->ether_dhost, origEthHdr->ether_shost, ETHER_ADDR_LEN);
  memcpy(ethHdr->ether_shost, origEthHdr->ether_dhost, ETHER_ADDR_LEN);
  ethHdr->ether_type = htons(ethertype_ip);  /* Tipo de protocolo IP */

  /* COLOQUE AQUÍ SU CÓDIGO*/

  /* Imprimir cabezales */ 
  printf("$$$ -> Imprimir cabezales antes de enviar el paquete ICMP error.\n");
  
  print_hdrs(icmpPacket, icmpPacketLen);

  /* -- Enviar el paquete ICMP -- */
  struct sr_rt* match = longest_prefix_match(sr, ipDst);
  printf("Interface: %s\n",  match->interface);
  sr_send_packet(sr, icmpPacket, icmpPacketLen, match->interface);

  /* Liberar memoria asignada */
  free(icmpPacket);
  printf("$$$ -> Sending error icmp.\n");
} /* -- sr_send_icmp_error_packet -- */


/*-----------------------------------------------------------------------------------------------------------------*/
/*-----------------------------------------------------------------------------------------------------------------*/
/*-------------------------------------HANDLE IP PACKET------------------------------------------------------------*/
/*-----------------------------------------------------------------------------------------------------------------*/
/*-----------------------------------------------------------------------------------------------------------------*/


void sr_handle_ip_packet(struct sr_instance *sr,
        uint8_t *packet /* lent */,
        unsigned int len,
        uint8_t *srcAddr,
        uint8_t *destAddr,
        char *interface /* lent */,
        sr_ethernet_hdr_t *eHdr) {

    printf("|||||||||||||||||||---STARTING---|||||||||||||||||||\n");

    sr_ip_hdr_t *ipHdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));

    /* Verificar checksum del cabezal ip */
    uint16_t sum = ipHdr->ip_sum;
    ipHdr->ip_sum = 0;
    uint16_t new_sum = ip_cksum(ipHdr, sizeof(sr_ip_hdr_t));
    ipHdr->ip_sum = sum;
    if (new_sum != sum) {
        printf("checksumIp invalid");
    }

    /* Verificar si el paquete es para una de mis interfaces */
    struct sr_if *myInterface = sr_get_interface_given_ip(sr, ipHdr->ip_dst);
    
    if (myInterface) {

        printf("**** -> IP packet is for me.\n");
        if (ipHdr->ip_p == ip_protocol_icmp) {
            sr_icmp_hdr_t *icmpHdr = (sr_icmp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

            /* CASE ECHO REPLY */
            if (icmpHdr->icmp_type == 8 && icmpHdr->icmp_code == 0) {
                printf("**** -> ICMP echo request received, sending echo reply.\n");

                /* Cambiar el tipo a Echo Reply (0) y recalcular el checksum ICMP */
                icmpHdr->icmp_type = 0;
                icmpHdr->icmp_code = 0;
                icmpHdr->icmp_sum = 0;
                icmpHdr->icmp_sum = cksum(icmpHdr, len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));

                /* Intercambiar las direcciones IP de origen y destino en el encabezado IP */
                uint32_t temp_ip = ipHdr->ip_src;
                ipHdr->ip_src = ipHdr->ip_dst;
                ipHdr->ip_dst = temp_ip;
                ipHdr->ip_sum = 0;
                ipHdr->ip_sum = cksum(ipHdr, sizeof(sr_ip_hdr_t));

                /* Buscar en la tabla de enrutamiento si hay coincidencia */
                struct sr_rt *match = longest_prefix_match(sr, ipHdr->ip_dst);

                /* No hay coincidencia en la tabla de enrutamiento */
                if (!match) {
                    printf("**** -> No matching route, sending ICMP net unreachable.\n");
                    sr_send_icmp_error_packet(3, 0, sr, ipHdr->ip_src, packet);
                    printf("$$$ -> Sent sr_send_icmp_error_packet complete ICMP net unreachable.\n");
                    return;
                }else {
                    /* Buscar la dirección MAC de la interfaz en la tabla ARP */
                        
                    /* print_addr_ip_int(sr->cache.entries[0].ip) */
                    struct sr_arpentry *arpEntry = sr_arpcache_lookup(&(sr->cache), match->gw.s_addr);

                    if (arpEntry) {
                      /* Reenviar el paquete si hay coincidencia en la tabla ARP */
                      printf("**** -> Returning IP packet.\n");

                      memcpy(eHdr->ether_dhost, arpEntry->mac, ETHER_ADDR_LEN);
                      memcpy(eHdr->ether_shost, destAddr, ETHER_ADDR_LEN);

                      printf("Interface: %s\n",  match->interface);
                      sr_send_packet(sr, packet, len, match->interface);
                      /* free(arpEntry); */

                      printf("$$$ -> Sent sr_send_packet complete luego de conseguir la mac directamente.\n");
                      return;
                  } else {
                      /* Solicitar ARP si no hay coincidencia y poner el paquete en espera */
                      printf("**** -> No ARP entry, sending ARP request and queueing packet.\n");

                      struct sr_arpreq *arpReq = NULL;  

                      if (match->gw.s_addr == htonl(INADDR_ANY)) {
                          printf("-------------DEFAULT ROUTE-------------\n");
                          arpReq = sr_arpcache_queuereq(&(sr->cache), ipHdr->ip_dst, packet, len, match->interface);
                      } else {
                          printf("-------------NEXT ROUTE-------------\n");
                          arpReq = sr_arpcache_queuereq(&(sr->cache), match->gw.s_addr, packet, len, match->interface);
                      }

                      if (arpReq) {
                          printf("---------------- HANDLING ARP REQ ----------------------\n");
                          handle_arpreq(sr, arpReq);
                      }
                      return;
                    }
                }
            }
        } else {
            printf("**** -> CARGA TCP o UDP, sending ICMP Port unreachable.\n");
            sr_send_icmp_error_packet(3, 3, sr, ipHdr->ip_src, packet);
        }

        /* Si no es ICMP, ignorar el paquete o manejar otros tipos */
        printf("Packet is for me but not an ICMP request, ignoring\n");
        return;
    } else {
        printf("**** -> IP packet isn't for me.\n");
        /* Verificar TTL */
        if (ipHdr->ip_ttl <= 1) {
            printf("**** -> TTL expired, sending ICMP TTL exceeded.\n");
            sr_send_icmp_error_packet(11, 0, sr, ipHdr->ip_src, packet);
            printf("$$$ -> Sent sr_send_icmp_error_packet complete ICMP TTL exceeded.\n");
            return;
        }

        /* Buscar en la tabla de enrutamiento si hay coincidencia */
        struct sr_rt *match2 = longest_prefix_match(sr, ipHdr->ip_dst);

        /* No hay coincidencia en la tabla de enrutamiento */
        if (!match2) {
            printf("**** -> No matching route, sending ICMP net unreachable.\n");
            sr_send_icmp_error_packet(3, 0, sr, ipHdr->ip_src, packet);
            printf("$$$ -> Sent sr_send_icmp_error_packet complete ICMP net unreachable.\n");
            return;
        } else {
            /* Si hay coincidencia en la tabla de enrutamiento */
            ipHdr->ip_ttl--;
            ipHdr->ip_sum = 0;
            ipHdr->ip_sum = ip_cksum(ipHdr, sizeof(sr_ip_hdr_t));

            /* Buscar la dirección MAC de la siguiente interfaz en la tabla ARP */
            printf("NEXT HOP: \n");
            print_addr_ip_int(match2->gw.s_addr);

            struct sr_arpentry *arpEntry = NULL;  

            if (match2->gw.s_addr == htonl(INADDR_ANY)) {
                arpEntry = sr_arpcache_lookup(&(sr->cache), ipHdr->ip_dst);
            } else {
                arpEntry = sr_arpcache_lookup(&(sr->cache), match2->gw.s_addr);
            }

            if (arpEntry) {

              printf("MAC Address: %02x:%02x:%02x:%02x:%02x:%02x\n",
              arpEntry->mac[0],
              arpEntry->mac[1],
              arpEntry->mac[2],
              arpEntry->mac[3],
              arpEntry->mac[4],
              arpEntry->mac[5]);

                /* Reenviar el paquete si hay coincidencia en la tabla ARP */
                printf("**** -> Forwarding IP packet.\n");
                printf("FROM:");
                print_addr_eth(sr_get_interface(sr,match2->interface)->addr);
                printf("TO:");
                print_addr_eth(arpEntry->mac);
                memcpy(eHdr->ether_shost, sr_get_interface(sr,match2->interface)->addr, ETHER_ADDR_LEN);
                memcpy(eHdr->ether_dhost, arpEntry->mac, ETHER_ADDR_LEN);

                printf("Interface: %s\n",  match2->interface);
                sr_send_packet(sr, packet, len, match2->interface);
                /* free(arpEntry); */

                printf("$$$ -> Sent sr_send_packet complete luego de conseguir la mac directamente.\n");
                return;
            } else {
                /* Solicitar ARP si no hay coincidencia y poner el paquete en espera */
                printf("**** -> No ARP entry, sending ARP request and queueing packet.\n");

                struct sr_arpreq *arpReq = NULL;  

                if (match2->gw.s_addr == htonl(INADDR_ANY)) {
                    printf("-------------DEFAULT ROUTE-------------\n");
                    arpReq = sr_arpcache_queuereq(&(sr->cache), ipHdr->ip_dst, packet, len, match2->interface);
                } else {
                    printf("-------------NEXT ROUTE-------------\n");
                    arpReq = sr_arpcache_queuereq(&(sr->cache), match2->gw.s_addr, packet, len, match2->interface);
                }

                if (arpReq) {
                    printf("---------------- HANDLING ARP REQ ----------------------\n");
                    handle_arpreq(sr, arpReq);
                }
                return;
            }

        }
    }
}


/*
TO DO:
Me queda cambiar lo de nameInterface a lo que devuelve la funcion logest_pef..() -> interface
Cambiar a que mande eso la busqueda de la cache
*/


/*--------------------------------------------------------------------------------------------------------------------------------------*/
/*--------------------------------------------------------------------------------------------------------------------------------------*/
/*-----------------------------------------------------FIN------------------------------------------------------------------------------*/
/*--------------------------------------------------------------------------------------------------------------------------------------*/
/*--------------------------------------------------------------------------------------------------------------------------------------*/


/* 
* ***** A partir de aquí no debería tener que modificar nada ****
*/

/* Envía todos los paquetes IP pendientes de una solicitud ARP */
void sr_arp_reply_send_pending_packets(struct sr_instance *sr,
                                        struct sr_arpreq *arpReq,
                                        uint8_t *dhost,
                                        uint8_t *shost,
                                        struct sr_if *iface) {

  struct sr_packet *currPacket = arpReq->packets;
  sr_ethernet_hdr_t *ethHdr;
  uint8_t *copyPacket;

  while (currPacket != NULL) {
     ethHdr = (sr_ethernet_hdr_t *) currPacket->buf;
     memcpy(ethHdr->ether_shost, dhost, sizeof(uint8_t) * ETHER_ADDR_LEN);
     memcpy(ethHdr->ether_dhost, shost, sizeof(uint8_t) * ETHER_ADDR_LEN);

     copyPacket = malloc(sizeof(uint8_t) * currPacket->len);
     memcpy(copyPacket, ethHdr, sizeof(uint8_t) * currPacket->len);

     print_hdrs(copyPacket, currPacket->len);
     printf("Interface: %s\n",  iface->name);
     sr_send_packet(sr, copyPacket, currPacket->len, iface->name);
     currPacket = currPacket->next;
  }
}

/* Gestiona la llegada de un paquete ARP*/
void sr_handle_arp_packet(struct sr_instance *sr,
        uint8_t *packet /* lent */,
        unsigned int len,
        uint8_t *srcAddr,
        uint8_t *destAddr,
        char *interface /* lent */,
        sr_ethernet_hdr_t *eHdr) {

  /* Imprimo el cabezal ARP */
  printf("*** -> It is an ARP packet. Print ARP header.\n");
  print_hdr_arp(packet + sizeof(sr_ethernet_hdr_t));

  /* Obtengo el cabezal ARP */
  sr_arp_hdr_t *arpHdr = (sr_arp_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));

  /* Obtengo las direcciones MAC */
  unsigned char senderHardAddr[ETHER_ADDR_LEN], targetHardAddr[ETHER_ADDR_LEN];
  memcpy(senderHardAddr, arpHdr->ar_sha, ETHER_ADDR_LEN);
  memcpy(targetHardAddr, arpHdr->ar_tha, ETHER_ADDR_LEN);

  /* Obtengo las direcciones IP */
  uint32_t senderIP = arpHdr->ar_sip;
  uint32_t targetIP = arpHdr->ar_tip;
  unsigned short op = ntohs(arpHdr->ar_op);

  /* Verifico si el paquete ARP es para una de mis interfaces */
  struct sr_if *myInterface = sr_get_interface_given_ip(sr, targetIP);

  if (op == arp_op_request) {  /* Si es un request ARP */
    printf("**** -> It is an ARP request.\n");

    /* Si el ARP request es para una de mis interfaces */
    if (myInterface != 0) {
      printf("***** -> ARP request is for one of my interfaces.\n");

      /* Agrego el mapeo MAC->IP del sender a mi caché ARP */
      printf("****** -> Add MAC->IP mapping of sender to my ARP cache.\n");
      sr_arpcache_insert(&(sr->cache), senderHardAddr, senderIP);

      /* Construyo un ARP reply y lo envío de vuelta */
      printf("****** -> Construct an ARP reply and send it back.\n");
      memcpy(eHdr->ether_shost, (uint8_t *) myInterface->addr, sizeof(uint8_t) * ETHER_ADDR_LEN);
      memcpy(eHdr->ether_dhost, (uint8_t *) senderHardAddr, sizeof(uint8_t) * ETHER_ADDR_LEN);
      memcpy(arpHdr->ar_sha, myInterface->addr, ETHER_ADDR_LEN);
      memcpy(arpHdr->ar_tha, senderHardAddr, ETHER_ADDR_LEN);
      arpHdr->ar_sip = targetIP;
      arpHdr->ar_tip = senderIP;
      arpHdr->ar_op = htons(arp_op_reply);

      /* Imprimo el cabezal del ARP reply creado */
      print_hdrs(packet, len);
      printf("Interface: %s\n",  myInterface->name);
      sr_send_packet(sr, packet, len, myInterface->name);
    }

    printf("******* -> ARP request processing complete.\n");

  } else if (op == arp_op_reply) {  /* Si es un reply ARP */

    printf("**** -> It is an ARP reply.\n");

    /* Agrego el mapeo MAC->IP del sender a mi caché ARP */
    printf("***** -> Add MAC->IP mapping of sender to my ARP cache.\n");
    struct sr_arpreq *arpReq = sr_arpcache_insert(&(sr->cache), senderHardAddr, senderIP);
    
    if (arpReq != NULL) { /* Si hay paquetes pendientes */

    	printf("****** -> Send outstanding packets.\n");
    	sr_arp_reply_send_pending_packets(sr, arpReq, (uint8_t *) myInterface->addr, (uint8_t *) senderHardAddr, myInterface);
    	sr_arpreq_destroy(&(sr->cache), arpReq);

    }
    printf("******* -> ARP reply processing complete.\n");
  }
}

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d \n",len);

  /* Obtengo direcciones MAC origen y destino */
  sr_ethernet_hdr_t *eHdr = (sr_ethernet_hdr_t *) packet;
  uint8_t *destAddr = malloc(sizeof(uint8_t) * ETHER_ADDR_LEN);
  uint8_t *srcAddr = malloc(sizeof(uint8_t) * ETHER_ADDR_LEN);
  memcpy(destAddr, eHdr->ether_dhost, sizeof(uint8_t) * ETHER_ADDR_LEN);
  memcpy(srcAddr, eHdr->ether_shost, sizeof(uint8_t) * ETHER_ADDR_LEN);
  uint16_t pktType = ntohs(eHdr->ether_type);

  if (is_packet_valid(packet, len)) {
    if (pktType == ethertype_arp) {
      sr_handle_arp_packet(sr, packet, len, srcAddr, destAddr, interface, eHdr);
    } else if (pktType == ethertype_ip) {
      sr_handle_ip_packet(sr, packet, len, srcAddr, destAddr, interface, eHdr);
    }
  }

}/* end sr_ForwardPacket */
