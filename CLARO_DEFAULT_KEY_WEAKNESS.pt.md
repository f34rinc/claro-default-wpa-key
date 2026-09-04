# Fraqueza da Chave Wi-Fi Padrão da Claro (`claro_wpa_key.py`)

🇧🇷 Português · [English](CLARO_DEFAULT_KEY_WEAKNESS.md)

Como a senha WPA2 padrão de fábrica de certos gateways Claro é derivada do MAC do
aparelho — de modo que pode ser **derivada** apenas de informação pública (ou
recuperada de um único handshake capturado), *desde que o gateway ainda esteja
com o SSID e a senha de fábrica* — por que o esquema é fraco, quais aparelhos são
afetados, e o que o `claro_wpa_key.py` automatiza.

> **Nota sobre as ilustrações:** todo endereço MAC, SSID, senha e hash *mostrado
> neste documento* é um exemplo fictício. Os achados são respaldados por
> aparelhos reais; a evidência por aparelho (com identificadores reais) é mantida
> em um arquivo privado que **não** faz parte deste repositório. Veja
> [§10, Evidências](#10-evidências).

> **Isto é específico do hardware afetado.** A fraqueza está presente em uma gama
> de gateways Claro mais antigos (aproximadamente 2021 e anteriores). Hardware
> mais novo (aproximadamente 2022 em diante) vem com chaves aleatórias de entropia
> completa e **não** é afetado. Veja
> [§11, Escopo](#11-escopo--quais-aparelhos-são-afetados).

---

## 1. TL;DR

Um gateway Claro afetado, em configuração de fábrica, transmite um SSID como
`CLARO_2G3A9C2D`. Duas coisas decorrem apenas desse nome:

- O SSID **vaza 6 dos 8** caracteres da senha Wi-Fi (são os últimos 6 hex do MAC
  do aparelho).
- Os 2 caracteres restantes são o 3º octeto do MAC — que faz parte do **OUI** do
  fabricante, e o **BSSID** do rádio Wi-Fi (em todo beacon) está nesse mesmo OUI.
  Então o byte "que falta" **normalmente também é legível.**

Efeito líquido: em aparelhos afetados, a chave inteira muitas vezes é derivável de
**informação pública de rádio** (BSSID + SSID) — sem handshake. No pior caso
(quando o último byte não pode ser lido do ar), é uma força bruta de **256
tentativas** contra um handshake capturado, resolvida offline em bem menos de um
segundo.

- **Força nominal** de uma chave WPA2 de 8 hex: 2³² (~4,3 bilhões).
- **Força real** em um aparelho afetado: **1 a 256 candidatos.**

Um colapso de 24 a 32 bits, de graça, só por estar no alcance do rádio.

---

## 2. Comando rápido

Se você tem um handshake em arquivo `.hc22000`, o ataque de fallback (forçar o
único byte incerto, com o final fixado pelo SSID) é uma linha só:

```bash
hashcat -a 3 -m 22000 capture.hc22000 ?H?H<ÚLTIMOS 6 HEX DO SSID>
```

Exemplo — SSID `CLARO_2G3A9C2D` (final = `3A9C2D`):

```bash
hashcat -a 3 -m 22000 capture.hc22000 ?H?H3A9C2D
```

- `-m 22000` — WPA-PBKDF2 (o formato de handshake `.hc22000`)
- `-a 3` — modo de máscara / força bruta
- `?H?H` — os 2 caracteres desconhecidos, hex **maiúsculo** `0-9A-F` (use `?H`, não `?h`) → 256 tentativas
- `3A9C2D` — o final literal de 6 hex do SSID = os **6 de 8** caracteres conhecidos da senha

Quebra em bem menos de um segundo. Ou deixe o script montar a máscara a partir da
captura:

```bash
python claro_wpa_key.py capture.hc22000
```

Muitas vezes você pode pular o handshake por completo — veja
[§5](#5-o-byte-inicial-normalmente-também-não-é-secreto).

---

## 3. O esquema da chave padrão

Em gateways afetados, tanto o SSID quanto a senha Wi-Fi são calculados a partir do
**MAC do aparelho** (o MAC do cable-modem/base — *não* o MAC do próprio rádio
Wi-Fi):

```
SSID padrão  = CLARO_<banda><últimos 6 hex do MAC>   ex.: CLARO_2G3A9C2D
senha padrão = <últimos 8 hex do MAC>, MAIÚSCULO      ex.: C23A9C2D
```

Mapeando para os octetos do MAC. Se o MAC do aparelho é `AA:BB:C2:3A:9C:2D`:

```
senha (8 hex)        = C2 3A 9C 2D    <- octetos 3,4,5,6 do MAC do aparelho
final do SSID (6 hex) =  3A 9C 2D      <- octetos 4,5,6 do MAC  (= caracteres 3-8 da senha)
```

Então, para `CLARO_2G3A9C2D`:

| Parte                    | Valor      | Origem                                   |
|--------------------------|------------|------------------------------------------|
| final de 6 hex do SSID   | `3A9C2D`   | transmitido no beacon                    |
| = caracteres 3-8 da senha| `..3A9C2D` | **conhecido por qualquer um no alcance** |
| caracteres 1-2 da senha  | `C2`       | octeto 3 do MAC do aparelho — veja §5    |
| senha completa           | `C23A9C2D` | hex maiúsculo `0-9A-F`                    |

O login de administrador é derivado da mesma forma nas unidades afetadas (usuário
`CLARO_<últimos 6 hex>`, senha = o MAC completo de 12 hex), agravando a exposição.

---

## 4. Por que o vazamento do SSID importa: a propriedade de handshake offline

O WPA2-PSK autentica com um handshake de 4 vias. Qualquer um que capture esse
handshake — passivamente, ou forçando uma reconexão com um deauth — pode testar
tentativas de senha **offline**: sem interação com o AP, sem bloqueio, sem limite
de taxa, tão rápido quanto o hardware permitir.

Então uma rede WPA2 só é tão forte quanto a *adivinhabilidade* de sua senha. Aqui
o espaço da senha é no máximo 256, então o handshake é uma formalidade —
milissegundos para testar todas.

O artefato capturado é uma linha hashcat `-m 22000`:

```
WPA*02*<MIC>*<AP MAC>*<client MAC>*<ESSID hex>*<nonce>*<eapol>*<msg-pair>
```

O `claro_wpa_key.py` extrai o hex do ESSID dessa linha para descobrir o SSID,
depois deriva a lista de candidatos — sem precisar do MAC do aparelho.

---

## 5. O byte inicial normalmente *também* não é secreto

> **Isto corrige uma versão anterior deste documento,** que afirmava que o byte
> inicial precisava ser forçado por bruta ao longo de 256 valores porque "o rádio
> Wi-Fi e o modem usam blocos de MAC não relacionados". A medição contra
> aparelhos reais mostra que isso está errado.

O byte inicial da senha é o **octeto 3** do MAC do aparelho — e o octeto 3 é o
último byte do **OUI** de 3 octetos do fabricante. No **gateway single-OUI
comum**, o **rádio Wi-Fi e o cable modem compartilham esse OUI** (os MACs de suas
interfaces ficam em um bloco de fabricante), então o **BSSID** do rádio —
transmitido em todo beacon — carrega o mesmo octeto 3 do MAC do modem que gera a
senha:

```
BSSID  (rádio, em todo beacon) = A0:B1:C2 : xx:xx:xx      OUI = A0:B1:C2
MAC do aparelho (gera a senha) = A0:B1:C2 : 3A:9C:2D      OUI = A0:B1:C2  (mesmo)
                                   ^^^^^
senha  = C2 3A9C2D            <- byte inicial C2 = octeto 3 do OUI = octeto 3 do BSSID
```

Então, em um aparelho single-OUI, a **chave completa é derivável de dados públicos
de rádio (BSSID + SSID) sem handshake nenhum** — uma única tentativa que você
simplesmente experimenta contra a rede. Ao longo de mais de 1.000 gateways
distintos com SSID de fábrica ativos (veja [§10](#10-evidências)), isso é a norma
— com a ressalva de split-OUI observada a seguir.

**A exceção — gateways split-OUI.** Alguns aparelhos — de forma **sistemática**,
os modelos ARRIS/CommScope — colocam o rádio Wi-Fi e o cable modem em **blocos de
OUI diferentes** — ex.: rádio `C8:52:61:…` enquanto o modem que gera a senha é
`A8:70:5D:…`. Aí o octeto 3 do BSSID (`61`) **não** é o byte inicial da senha
(`5D`), então não pode ser lido do beacon. É exatamente para este caso que existe
o fallback de **256 tentativas**: fixe o final de 6 hex do SSID e force por bruta
o único byte inicial contra um handshake.

Uma ressalva crucial sobre o quão comum isso é: **o split não pode ser detectado
apenas por um beacon.** O SSID vaza o final do *modem* enquanto o BSSID pertence
ao *rádio*; em uma unidade single-OUI eles compartilham o octeto 3, em uma unidade
split não — mas o octeto 3 do modem nunca é transmitido, então distinguir os dois
exige um MAC de etiqueta ou um handshake. Em nossas varreduras de metrópole, os
gateways com SSID de fábrica foram dominados por fabricantes single-OUI e as
unidades split mal apareceram nessa população — mas isso **não** é evidência de
que o hardware split seja raro. Dois efeitos o escondem: gateways split que foram
**renomeados** saem inteiramente da população de SSID padrão (não dá para derivar
uma rede renomeada), e uma unidade split em qualquer bloco de OUI da CommScope que
não catalogamos aparece como single-OUI para uma varredura passiva. Buscar
diretamente nessas mesmas capturas pelo OUI de roteador da ARRIS revelou **três**
unidades ARRIS distintas — todas com SSID renomeado. Então trate single-OUI como
a norma **entre os fabricantes confirmados como bloco único**, e trate
ARRIS/CommScope como uma classe split real e não rara que uma varredura só de
beacon **subconta** sistematicamente.

Na prática: **tente `octeto 3 do BSSID + final do SSID` primeiro** (uma tentativa
— funciona na maioria single-OUI); se falhar, recorra à máscara de 256 tentativas
(cobre a minoria split-OUI). O `claro_wpa_key.py` faz os dois automaticamente.

---

## 6. Espaço de chaves dedutivo: atacar com o que o beacon já revela

A chave é uma *fatia do MAC*, e os caracteres hex do MAC estão à mostra no BSSID
(o OUI) e no SSID (o final). Isso torna possível atacar a chave **dedutivamente**
— com um conjunto de candidatos que você pode *provar* que contém a resposta — em
vez de forçar por bruta todo o espaço hex de 2³². Ordenado do mais barato primeiro:

1. **Derivar e conectar (1 tentativa, sem handshake).** `<octeto 3 do BSSID> +
   <final do SSID>`. Em um aparelho afetado, isso *é* a chave; é só experimentar.
2. **Lista de combinações de octetos (~milhares, instantâneo).** Pegue os octetos
   distintos de 2 hex vistos no BSSID + SSID e teste toda combinação de 4 octetos
   como uma pequena wordlist (`hashcat -a 0`). Garantidamente contém a chave
   quando os octetos da chave vêm do beacon.
3. **Máscara de charset reduzido (instantâneo→minutos).** Monte um charset
   personalizado do hashcat apenas com os caracteres hex presentes nas sequências
   hex do BSSID + SSID, ao longo das 8 posições. Implementado por
   [`utils/charset_mask.py`](utils/charset_mask.py).
4. **Máscara completa (fallback).** `?H?H<final>` (256) se você confia no final,
   ou todo o espaço hex de 2³² como último recurso (~8 h em uma GPU de consumo a
   ~150 kH/s — note que mesmo *isto* não é realmente "seguro").

Cada nível é um conjunto sobre o qual você pode raciocinar, não uma adivinhação
probabilística. Os níveis 1–3 são efetivamente instantâneos.

---

## 7. O que o `claro_wpa_key.py` faz

1. **Analisa** o arquivo `.hc22000` → extrai o `{essid, bssid}` de cada rede.
2. **Reconhece** SSIDs Claro padrão e extrai o final de 6 hex do aparelho —
   tratando toda variante de campo: `CLARO_<banda><6hex>`, sem banda
   `CLARO_<6hex>`, backhaul de mesh `…-5G-BH`, `…-IoT`, e o raro SSID com 8 hex
   completos. Redes renomeadas (ex.: `CLARO_MOVEL`) são ignoradas.
3. **Consulta o OUI do BSSID** numa tabela de blocos de fabricantes Claro
   conhecidos (informativo — rotula o fabricante e sinaliza o bloco split-OUI da
   ARRIS).
4. **Calcula a chave mais provável** = `<octeto 3 do BSSID> + <final do SSID>`
   (nível 1) e a imprime para experimentar direto — sem handshake em gateways
   single-OUI.
5. **Verifica / recorre com o hashcat** `-m 22000 -a 3`: tenta primeiro a chave
   provável de 1 tentativa; se falhar (split-OUI), força por bruta o byte inicial
   com `?H?H<final>` (256). Informa qual caminho quebrou (single- ou split-OUI).

A máscara de charset reduzido (nível 3) está em
[`utils/charset_mask.py`](utils/charset_mask.py); os níveis 1–2 são os atalhos
dedutivos descritos em §5–§6, agora embutidos na ferramenta principal.

---

## 8. Exemplo prático (fictício, ilustrativo)

- **SSID:** `CLARO_2G3A9C2D`  (hex `434c41524f5f3247334139433244`)
- **BSSID (rádio Wi-Fi, no beacon):** `A0:B1:C2:0C:E4:59` → OUI `A0:B1:C2`, octeto 3 `C2`
- **MAC do aparelho (gera a senha):** `A0:B1:C2:3A:9C:2D` (mesmo OUI do rádio)
  → senha = últimos 8 hex = `C23A9C2D`; final do SSID = últimos 6 hex = `3A9C2D`
- **Conhecido a partir de dados públicos de rádio:** final `3A9C2D` (SSID) +
  inicial `C2` (octeto 3 do BSSID) = **`C23A9C2D`** — a chave inteira, sem handshake.
- **Fallback (se o octeto 3 não puder ser lido):** `hashcat -m 22000 -a 3 <arquivo> ?H?H3A9C2D` → 256 tentativas.
- **Senha derivada: `C23A9C2D`**

O byte inicial `C2` **é igual** ao octeto 3 do BSSID do rádio — porque o rádio e o
aparelho estão no mesmo OUI do fabricante, que é exatamente por que o byte não é
secreto.

---

## 9. A fraqueza, generalizada

Em aparelhos afetados, isto é uma falha clássica de **credencial padrão de
fabricante** — quatro erros de projeto que se acumulam:

1. **Derivação determinística a partir de uma semente de baixa entropia.** A chave
   é uma função pura do MAC. Um MAC é um identificador, não material de chave
   aleatório.
2. **A semente é transmitida.** O SSID publica os últimos 3 octetos do MAC, e o
   BSSID publica o OUI (octeto 3) — juntos, todos os 4 octetos da senha.
3. **Um alfabeto minúsculo, sem alongamento.** Apenas hex maiúsculo, nunca
   expandido por hashing ou um conjunto maior de caracteres. 8 hex = 32 bits no
   máximo; após os vazamentos, tão pouco quanto 0.
4. **Protocolo atacável offline.** O handshake capturado do WPA2 torna até um
   espaço trivial totalmente testável, sem detecção ou bloqueio — e aqui você
   muitas vezes nem precisa dele.

Qualquer um é sobrevivível. Juntos, eles reduzem uma rede WPA2 "forte" a uma
consulta.

### É uma família inteira

Este padrão não é exclusivo da Claro. O mesmo problema de
chave-padrão-de-engenharia-reversa atingiu muitas linhas de ISP/fabricante —
Thomson/SpeedTouch, BT Home Hub, UPC/Ubee, Arcadyan, Sky, e outras. Sempre que uma
chave padrão é um algoritmo sobre um identificador público, esse algoritmo acaba
sendo publicado e os padrões de toda a frota se tornam recuperáveis.

---

## 10. Evidências

Os achados acima são empíricos, não teóricos. Foram verificados contra **10
gateways Claro de 7 fabricantes de hardware**, usando uma mistura de
handshake-e-derivação ao vivo, fotografias de etiquetas de fábrica, imagens de
homologação da ANATEL, e dados de QR/código de barras nas etiquetas:

| Grupo | Qtd. | Fabricantes | Datas de fab. | Senha |
|-------|------|-------------|---------------|-------|
| **Afetados** (chave derivada do MAC) | 5 | 5 distintos | 2019–2021 | = últimos 8 hex do MAC |
| **Não afetados** (chave aleatória)   | 5 | (2 repetidos) | 2022+     | aleatória de entropia completa |

- Nos aparelhos afetados, a senha Wi-Fi é igual aos últimos 8 hex do MAC do
  aparelho — **verificado derivando a chave de um handshake de 4 vias ao vivo em 2
  unidades** (PBKDF2/PTK/MIC em Python puro apenas sobre os candidatos derivados
  do SSID), e lendo o MAC + senha impressos nas demais.
- Nos aparelhos single-OUI, o **byte inicial da senha = octeto 3 do BSSID Wi-Fi** —
  verificado contra BSSIDs capturados em 2 unidades e o bloco MAC impresso nas
  outras. A única unidade **split-OUI** (uma ARRIS: Wi-Fi `C8:52:61`, modem
  `A8:70:5D`) foi confirmada lendo ambos os MACs de sua página de administração —
  o caso que o fallback de 256 tentativas trata.
- O SSID = `CLARO_<banda><últimos 6 hex do MAC>` em **todos os 10** aparelhos,
  afetados ou não — então o formato do SSID sozinho **não** indica vulnerabilidade.

### Corroboração em escala (varredura passiva)

Além dos 10 aparelhos em mãos, uma varredura passiva de wardriving de uma área
metropolitana (capturas recentes, **1.021 gateways Claro distintos com SSID de
fábrica** — 1.389 BSSIDs antes de agrupar os rádios secundários de cada unidade —
após deduplicação) confirma que o padrão é **difundido e atual**, não anedótico:

- **1.021 gateways distintos** ainda transmitiam um SSID `CLARO_<...>` de fábrica —
  cada um vazando o final de 6 hex, em **mais de 20 blocos de OUI de fabricantes**
  (Kaon, Humax, Compal, Sagemcom, ZTE, Vantiva/Technicolor, MitraStar, e mais).
- Contando os rádios de convidado / backhaul de mesh (`-5G-BH`) / IoT de um
  gateway: esses BSSIDs extras são o mesmo MAC com o **bit de administração local
  invertido** no octeto 1 — que nunca toca o octeto 3 — então o byte inicial ainda
  é lido do beacon neles também. Eles inflam a contagem de BSSIDs, mas não a
  contagem de gateways.
- Para todo gateway com SSID de fábrica na varredura, a relação byte inicial =
  octeto 3 do BSSID se manteve: a população é **dominada por single-OUI**, e o
  candidato derivado bateu onde pudemos verificar (as duas unidades quebradas por
  handshake e as confirmadas por etiqueta). Algumas tinham o MAC do rádio a poucos
  do MAC do modem (atribuição clássica de bloco único); outras com deslocamentos
  maiores **dentro do mesmo OUI**, onde o byte ainda é o octeto 3 do BSSID.
- **Sobre o hardware split — leia com atenção.** Unidades split-OUI
  (ARRIS/CommScope) mal apareceram *na população de SSID padrão*, mas isso **não**
  é evidência de que o hardware split seja raro, e não afirmamos que seja. O split
  não pode ser visto apenas de um beacon, e unidades split que foram **renomeadas**
  saem inteiramente da população de SSID padrão. Buscar nessas mesmas capturas
  diretamente pelo OUI de roteador da ARRIS (`C8:52:61`) encontrou **três gateways
  ARRIS distintos — cada um com SSID renomeado** (duas unidades de vizinhos, não
  apenas a inspecionada fisicamente). Então a leitura honesta é: "uma tentativa a
  partir do beacon" é o caso comum **para a população de SSID padrão dominada por
  single-OUI** que a ferramenta mira — enquanto ARRIS/CommScope é uma classe split
  real que uma varredura passiva **subconta sistematicamente**, não uma raridade.
- Apenas contagens agregadas são relatadas aqui; a varredura bruta (que carrega
  coordenadas GPS por AP) **não** é publicada.

> A tabela completa por aparelho — modelos reais, MACs, SSIDs, senhas, datas e
> fontes — é mantida em um `EVIDENCE.md` local que é **git-ignored** e nunca
> publicado, porque contém material de credencial real. Este documento público
> carrega deliberadamente apenas contagens agregadas e ilustrações fictícias.

---

## 11. Escopo — quais aparelhos são afetados

- **A fraqueza é específica de modelo/época, não universal, e não específica de
  fabricante.** As unidades afetadas observadas foram fabricadas **~2021 e antes**;
  unidades de **~2022 em diante** vêm com chaves aleatórias de entropia completa e
  **não** são afetadas. O mesmo fabricante pode aparecer nos dois lados (modelo
  mais antigo vulnerável, mais novo não), então nem o OUI do fabricante nem o nome
  do SSID `CLARO_` te dizem — **trate qualquer SSID `CLARO_<banda><hex>` como *vale
  testar*, nunca como *garantidamente vulnerável*.** A ferramenta simplesmente
  falha (nenhum candidato bate) em um aparelho de chave aleatória, o que é a
  resposta correta.
- Funciona **apenas** enquanto um gateway estiver com seu **SSID + senha padrão de
  fábrica**. Um SSID renomeado ou uma senha alterada não podem ser derivados desta
  forma — que é exatamente por que trocar o padrão é a correção.
- A transição para chaves aleatórias foi observada entre **07/2021** (última
  unidade afetada vista) e **07/2022** (primeira unidade de chave aleatória vista).

---

## 12. Orientação defensiva

**Para um dono de gateway:**

- **Troque a senha Wi-Fi** por uma frase-senha longa e aleatória (a correção
  real). Uma frase-senha aleatória de 20+ caracteres derrota a força bruta offline
  por completo.
- **Troque o SSID** para que não ecoe mais o MAC. Por si só, isso apenas esconde o
  hex vazado; **não** corrige uma senha ainda padrão, então faça os dois.
- Trate qualquer aparelho ainda com seu nome de fábrica `CLARO_<banda><hex>` como
  efetivamente aberto, e verifique se o seu é um dos modelos afetados (pré-2022).

**Para o fabricante/ISP (causa raiz):**

- Provisione chaves Wi-Fi **aleatórias por aparelho, de entropia completa**,
  geradas e armazenadas, não calculadas a partir do MAC. *(O hardware 2022+ da
  Claro já faz isso — a correção está comprovada e em produção; o risco residual é
  a base instalada de unidades mais antigas.)*
- **Nunca derive o SSID e a chave do mesmo segredo**, e nunca embuta material de
  chave em um campo transmitido.
- Force uma troca de senha na primeira configuração.

---

## 13. Arquivos

| Arquivo                     | Papel                                                      |
|-----------------------------|------------------------------------------------------------|
| `claro_wpa_key.py`          | analisa `.hc22000`, monta a máscara, dirige o hashcat      |
| `utils/charset_mask.py`     | máscara de charset reduzido a partir do hex do BSSID + SSID |
| `*.hc22000` / `EVIDENCE.md` | capturas e o arquivo de evidência real — **não** distribuídos |
| `hashcat.exe`               | o quebrador (`-m 22000 -a 3`) — instalado separadamente    |

> Capturas `*.hc22000`, `hashcat.exe`, e `EVIDENCE.md` **não** estão neste
> repositório. Capturas e o arquivo de evidência são material de credencial real e
> são excluídos pelo `.gitignore`; instale o hashcat separadamente.

*Apenas para auditoria autorizada / equipamento próprio ou consentido.*
