#include "capture.h"

#include <memory.h>
#include <ctype.h>

/*
* Inicializa as estruturas de captura de pacote
*/
int init_capture(){
    int count;
    char *device; // Dispositivo de captura utilizado
    pcap_t *descr;
    // Preenche todos os espacos do buffer de erro com zero
    memset(errbuf, 0, PCAP_ERRBUF_SIZE);
    // Recupera o nome do primeiro dispositivo de rede disónível para captura
    device = pcap_lookupdev(errbuf);
    printf("%s\n", device);
    if (device == NULL) {

        printf("%s\n", errbuf);
        return -1;
    }

    // Abre o dispositivo recuperado
    descr = pcap_open_live(device, 65555, 1, 512, errbuf);

    printf("%s\n", errbuf);

    /*Loop para aplicar a funcao process_packet para cada pacote capturado*/
    pcap_loop(descr, -1, process_packet, (u_char *) &count);
}

void process_packet(u_char *args, const struct pcap_pkthdr *pkthdr, const u_char *packet_bytes) {
    int i = 0, *counter = (int*) args;

    printf("Contador de pacotes: %d\n", ++(*counter));
    printf("Tamanho do pacote recebido: %d\n", pkthdr->len);
    printf("Payload: \n");

    for(i = 0; i < pkthdr->len; i++){

        if(isprint(packet_bytes[i])) {
            printf("%c ", packet_bytes[i]);
        }
        else {
            printf(". ");
        }

        if((i%16 == 0 && i != 0) || i == pkthdr->len - 1){
            printf("\n");
        }
    }
}
