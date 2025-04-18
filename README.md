# **Dataplane Router - Tema 1 PCom**
*Copyright Mantu Ionut Gabriel- 323CA*

## **Descriere**
Aceasta tema a avut ca scop implementarea dataplane-ului unui router software, conform cerintelor specifice. Functionalitatile implementate acopera urmatoarele:

- **Procesul de rutare IPv4**;
- **Protocolul ARP (Address Resolution Protocol)**;
- **Protocolul ICMP (Internet Control Message Protocol)**;
- **Longest Prefix Match (LPM) eficient folosind cautare binara**.

Testarea s-a realizat utilizand comenzi precum `ping`, `traceroute`, `arping` si analiza traficului cu `Wireshark` / `tcpdump`.

## **Implementare**

### **Procesul de Rutare**

La primirea unui pachet, router-ul parcurge urmatorii pasi:

1. **Verificarea destinatiei**: 
   - Verifica daca pachetul este destinat router-ului (adresa MAC corespunde interfetei locale sau este un pachet broadcast).

2. **Verificarea tipului pachetului**:
   - Verifica daca pachetul este de tip IPv4 sau ARP.

3. **Pentru un pachet IPv4**:
   - Se verifica integritatea header-ului IP prin recalcularea checksum-ului.
   - Se verifica valoarea TTL:
     - Daca TTL ≤ 1, pachetul este abandonat si se trimite un ICMP `Time Exceeded`.
     - Daca TTL > 1, TTL este decrementeaza, checksum-ul este recalcultat si se cauta ruta optima cu LPM.
   
4. **Daca router-ul este destinatia finala si pachetul este un ICMP Echo Request (ping)**:
   - Se construieste si se trimite un ICMP Echo Reply.

5. **Daca router-ul trebuie sa forwardeze pachetul**:
   - Se cauta ruta optima cu LPM.
   - Daca nu exista ruta, se trimite un ICMP `Destination Unreachable`.
   - Daca next-hop-ul nu are adresa MAC cunoscuta, se trimite un ARP Request si pachetul este pus intr-o coada.
   - Daca adresa MAC este cunoscuta, pachetul este forwardat.

---

### **Longest Prefix Match (LPM)**

Implementarea **LPM** s-a realizat folosind **cautare binara**, pentru a obtine o eficienta mai mare comparativ cu cautarea liniara.

1. **Sortarea tabelei de rutare**:
   - Inainte de a cauta cel mai lung prefix care se potriveste cu adresa IP destinatie, tabela de rutare este sortata. 
   - Fiecare intrare din tabela contine un **prefix** si o **masca de retea**.

2. **Cautarea binara**:
   - Cautarea binara este aplicata pentru a gasi prefixul care se potriveste cel mai bine cu adresa destinatie.
   - Practic, se compara prefixul si masca fiecarei rute cu adresa IP destinatie.

3. **Cum functioneaza cautarea binara**:
   - **Preprocesarea**: Tabela este sortata in functie de lungimea prefixului si a mastii.
   - **Cautarea**: La fiecare pas, se verifica daca adresa IP destinatie se potriveste cu prefixul respectiv.
     - Daca exista o potrivire exacta, aceasta devine cea mai buna ruta gasita pana in acel moment.
     - Daca prefixul este mai mic decat cel cautat, se continua cautarea in partea dreapta a tabelului, altfel se cauta in partea stanga.

4. **Beneficiul utilizarii cautarii binare**:
   - Timpul de cautare se reduce de la O(n) (in cazul cautarii liniare) la O(log n), ceea ce creste semnificativ performanta atunci cand tabela de rutare este mare.

---

### **Protocolul ARP**

La receptionarea unui **ARP Reply**:

- Se actualizeaza tabela ARP cu IP-ul si MAC-ul corespunzator.
- Daca exista pachete in asteptare pentru adresa respectiva, acestea sunt trimise.

La receptionarea unui **ARP Request**:

- Router-ul raspunde cu propriul MAC.

Daca nu exista MAC cunoscut pentru **next-hop**, router-ul trimite un **ARP Request broadcast** si pune pachetul intr-o coada de asteptare.

---

### **Protocolul ICMP**

Router-ul construieste si trimite mesaje ICMP in urmatoarele situatii:

1. **TTL Expirat**:
   - Se trimite un **ICMP Time Exceeded**.

2. **Destinatie inexistenta**:
   - Se trimite un **ICMP Destination Unreachable**.

3. **ICMP Echo Reply**:
   - Raspunde la cererile **ICMP Echo Request** (ping).

Structura pachetului ICMP construit contine urmatoarele header-e:

- **Ethernet Header**;
- **IPv4 Header**;
- **ICMP Header**.
