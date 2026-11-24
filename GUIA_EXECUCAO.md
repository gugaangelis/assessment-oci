# Guia de execução: Assessment OCI Well-Architected

Este guia cobre todos os passos para executar o `oci_assessment.py` em um tenancy Oracle Cloud (OCI): preparar o acesso, conectar no tenancy, rodar a coleta e baixar os relatórios.

---

## 1. Visão geral

O script faz um levantamento **somente leitura** do tenancy e avalia o ambiente contra os 5 pilares do OCI Well-Architected Framework:

- Segurança e conformidade
- Confiabilidade e resiliência
- Desempenho e custos
- Eficiência operacional
- Cloud distribuído

**Nenhum recurso é criado, alterado ou excluído.** Todo client do SDK passa por um proxy que só permite métodos de consulta (`list_`, `get_`, `search_`, `summarize_`). Qualquer outra chamada gera erro antes de chegar à OCI.

### Arquivos gerados

| Arquivo | Público | Conteúdo |
|---|---|---|
| `relatorio_executivo.pdf` | Liderança | Score, riscos principais, custos, roadmap 30/60/90 e próximos passos |
| `relatorio_tecnico.pdf` | Times de engenharia | Todas as lacunas com evidência, custos, segurança, observabilidade, inventário |
| `apresentacao_stakeholders.pptx` | Reunião com stakeholders | Até 13 slides 16:9, gráficos editáveis e notas do apresentador |
| `relatorio.html` | Geral | Relatório completo para abrir no navegador |
| `achados.csv` | Gestão do backlog | Lacunas por pilar, prioridade e recomendação |
| `cobertura_recursos.csv` | Engenharia | Cada recurso: tem alarme, log, métrica, tag? |
| `otimizacao_custos.csv` | FinOps | Desperdício e rightsizing por recurso, com custo real dos últimos 30 dias e economia estimada |
| `custos_por_recurso.csv` | FinOps | Top 25 recursos por custo, mês a mês, na janela de custos (padrão 90 dias) |
| `dados.json` | Reprocessamento | Dados brutos da coleta (permite regerar os relatórios sem nova coleta) |

### Tempo estimado

- Preparação de acesso (passos 2 e 3): 15 a 30 minutos, uma única vez.
- Execução: de 5 a 40 minutos, conforme o número de regiões, compartments e recursos.

---

## 2. Pré-requisitos

- Um usuário com acesso ao Console da OCI do tenancy a ser avaliado.
- Alguém com perfil de **administrador do tenancy** para criar o grupo e a policy do passo 3 (pode ser feito uma única vez pelo time do cliente).
- O arquivo `oci_assessment.py`.

Escolha onde executar:

| Opção | Quando usar |
|---|---|
| **A. OCI Cloud Shell** (recomendada) | Não exige instalar nada nem gerar chaves. O SDK `oci` já vem instalado. |
| **B. Máquina local** (Windows, Linux ou macOS) | Quando o Cloud Shell não estiver liberado ou para execuções recorrentes. Exige uma API key. |

---

## 3. Preparar o acesso no tenancy (administrador)

### 3.1 Criar o grupo

1. Entre no Console da OCI como administrador.
2. Menu ☰ → **Identity & Security** → **Domains**.
3. Selecione o domínio (normalmente `Default`) → **User management** → **Groups** → **Create group**.
4. Nome sugerido: `oci-assessment`.
5. Adicione ao grupo o usuário que vai executar o assessment.

### 3.2 Criar a policy

1. Menu ☰ → **Identity & Security** → **Policies**.
2. Selecione o compartment **root** (o próprio tenancy). A policy precisa estar no root para valer para todos os compartments.
3. **Create Policy** → nome sugerido: `oci-assessment-readonly`.
4. Ative **Show manual editor** e cole os statements:

```text
Allow group 'Default'/'oci-assessment' to inspect all-resources in tenancy
Allow group 'Default'/'oci-assessment' to read all-resources in tenancy
Allow group 'Default'/'oci-assessment' to read usage-reports in tenancy
Allow group 'Default'/'oci-assessment' to use cloud-shell in tenancy
Allow group 'Default'/'oci-assessment' to use cloud-shell-public-network in tenancy
```

Observações:

- Se o grupo estiver em outro identity domain, troque `'Default'` pelo nome do domínio.
- Em tenancies antigos, sem identity domains, use apenas o nome do grupo: `Allow group oci-assessment to ...`.
- As duas últimas linhas só são necessárias se for usar o **Cloud Shell** (opção A).
- `read usage-reports` libera a análise de custos (Usage API). Sem ela, o assessment roda, mas a seção de custos fica vazia.

> **Escopo parcial:** se o cliente não quiser liberar leitura no tenancy inteiro, os statements podem ser restritos a compartments específicos (`in compartment <nome>`). Nesse caso, rode o script com `--compartments` (ver seção 6). Itens sem permissão aparecem como "parcial" no Apêndice A do relatório técnico.

---

## 4. Opção A: executar no OCI Cloud Shell (recomendada)

### 4.1 Conectar no tenancy

1. Acesse <https://cloud.oracle.com>.
2. Informe o **Cloud Account Name** (nome do tenancy) → **Next**.
3. Selecione o identity domain (normalmente `Default`) e faça login com usuário, senha e MFA.
4. No topo do Console, confira a **região** selecionada. Qualquer região serve: o script descobre sozinho a home region e todas as regiões subscritas.

### 4.2 Abrir o Cloud Shell

1. Clique no ícone **Developer tools** (`>_`) no topo do Console → **Cloud Shell**.
2. Aguarde o terminal abrir na parte inferior da tela.
3. Confira a versão do Python (o script exige **3.10 ou superior**):

```bash
python3 --version
```

Se a versão for menor que 3.10, verifique se o Cloud Shell oferece outra versão com `csruntimectl python list`; se não houver, use a opção B (máquina local).

### 4.3 Enviar o script

1. No Cloud Shell, clique no menu de engrenagem (⚙) → **Upload**.
2. Selecione o arquivo `oci_assessment.py`.
3. O arquivo vai para o diretório home. Confira:

```bash
cd ~
ls -l oci_assessment.py
```

### 4.4 Instalar as bibliotecas dos relatórios

O SDK `oci` já vem instalado no Cloud Shell. Instale apenas as bibliotecas de PDF e PowerPoint:

```bash
pip3 install --user reportlab python-pptx
```

> Sem essas bibliotecas o script continua funcionando: gera HTML, CSV e JSON e apenas avisa no log que pulou os PDFs e o PPTX.

### 4.5 Executar

Teste rápido de conectividade (só lista as opções):

```bash
python3 oci_assessment.py --help
```

Execução completa (troque o nome do cliente):

```bash
python3 oci_assessment.py --customer "Nome do Cliente" --days 30
```

No Cloud Shell a autenticação é automática (`--auth auto` detecta o Cloud Shell e usa o token da sua sessão).

**Para tenancies grandes**, rode em segundo plano para não perder a execução se a sessão do Cloud Shell desconectar por inatividade:

```bash
nohup python3 oci_assessment.py --customer "Nome do Cliente" --days 30 > assessment.log 2>&1 &
tail -f assessment.log
```

(`Ctrl+C` encerra só o `tail`; a coleta continua.)

O fim da execução é indicado por uma linha como:

```text
[16:19:42] Concluído: score 36/100 · 1614 chamadas de leitura · saída em /home/usuario/oci-assessment-20261123-1619
```

### 4.6 Baixar os relatórios

1. Compacte a pasta gerada:

```bash
cd ~
zip -r assessment.zip oci-assessment-*/
```

2. Menu de engrenagem (⚙) → **Download** → informe `assessment.zip` → **Download**.
3. Descompacte no seu computador.

### 4.7 Limpeza

Os arquivos contêm inventário e configuração do ambiente do cliente. Depois de baixar:

```bash
rm -rf ~/oci-assessment-*/ ~/assessment.zip ~/assessment.log
```

---

## 5. Opção B: executar em uma máquina local

### 5.1 Instalar o Python e as bibliotecas

1. Instale o Python **3.10 ou superior** (<https://www.python.org/downloads/>).
2. Instale as dependências:

```bash
pip install oci reportlab python-pptx
```

### 5.2 Gerar a API key (conexão com o tenancy)

1. Faça login no Console da OCI (passo 4.1).
2. Clique no ícone do usuário (canto superior direito) → **My profile**.
3. Em **Resources**, clique em **API keys** → **Add API key**.
4. Escolha **Generate API key pair** e clique em **Download private key**. Guarde o arquivo `.pem` em local seguro.
5. Clique em **Add**. O Console mostra um trecho de configuração parecido com:

```ini
[DEFAULT]
user=ocid1.user.oc1..aaaa...
fingerprint=12:34:56:...
tenancy=ocid1.tenancy.oc1..aaaa...
region=sa-saopaulo-1
key_file=<path to your private keyfile>
```

### 5.3 Criar o arquivo de configuração

Crie o arquivo de configuração e cole o trecho do passo anterior, ajustando `key_file` para o caminho do `.pem` baixado.

| Sistema | Caminho do arquivo |
|---|---|
| Linux / macOS | `~/.oci/config` |
| Windows | `C:\Users\<usuario>\.oci\config` |

Recomendação: use um perfil com o nome do cliente em vez de `DEFAULT`, por exemplo `[CLIENTE]`. Assim é possível ter vários tenancies no mesmo arquivo.

Exemplo:

```ini
[CLIENTE]
user=ocid1.user.oc1..aaaa...
fingerprint=12:34:56:...
tenancy=ocid1.tenancy.oc1..aaaa...
region=sa-saopaulo-1
key_file=~/.oci/cliente_api_key.pem
```

No Linux/macOS, proteja os arquivos:

```bash
chmod 600 ~/.oci/config ~/.oci/cliente_api_key.pem
```

### 5.4 Executar

```bash
python oci_assessment.py --auth config --profile CLIENTE --customer "Nome do Cliente" --days 30
```

A pasta `oci-assessment-AAAAMMDD-HHMM` é criada no diretório atual.

> Ao final do trabalho, remova a API key do perfil do usuário no Console (**My profile** → **API keys** → **Delete**) e apague o `.pem` local.

---

## 6. Parâmetros

| Parâmetro | Padrão | Descrição |
|---|---|---|
| `--customer` | `Assaí Atacadista` | Nome do cliente exibido nos relatórios. **Sempre informe.** |
| `--auth` | `auto` | `auto`, `cloudshell`, `config` ou `instance_principal` |
| `--profile` | `DEFAULT` | Perfil do `~/.oci/config` (com `--auth config`) |
| `--config-file` | `~/.oci/config` | Caminho alternativo do arquivo de configuração |
| `--regions` | todas as subscritas | Regiões separadas por vírgula, ex.: `sa-saopaulo-1,sa-vinhedo-1` |
| `--compartments` | todos | Nomes ou OCIDs separados por vírgula (inclui os subcompartments) |
| `--days` | `30` | Janela do histórico de alarmes (máximo 90) |
| `--cost-days` | `90` | Janela da análise de custos (consultada mês a mês na Usage API) |
| `--expected-tools` | `dynatrace` | Ferramentas de observabilidade que o cliente diz usar (ex.: `dynatrace,grafana`) |
| `--scan-keywords` | `dynatrace,grafana,zabbix,...` | Termos procurados em recursos, policies e connectors |
| `--expected-clouds` | `azure` | Clouds com interconexão esperada |
| `--threads` | `8` | Paralelismo da coleta. Aumente (12 a 16) em tenancies grandes |
| `--max-alarm-history` | `500` | Máximo de alarmes com histórico analisado |
| `--max-backup-checks` | `3000` | Máximo de volumes com política de backup verificada |
| `--formats` | `pdf,pptx` | Saídas extras além de HTML/CSV/JSON. `pdf`, `pptx` ou `none` |
| `--out` | `oci-assessment-<data-hora>` | Pasta de saída |
| `--render-only` | — | Regera os relatórios a partir de um `dados.json` existente, sem acessar a OCI |

### Exemplos

```bash
# Tenancy inteiro, cliente que usa Dynatrace e Grafana
python3 oci_assessment.py --customer "Nome do Cliente" --expected-tools dynatrace,grafana

# Apenas duas regiões e compartments específicos
python3 oci_assessment.py --customer "Nome do Cliente" --regions sa-saopaulo-1,sa-vinhedo-1 --compartments "Prod,Shared"

# Tenancy grande: mais paralelismo e janela de 90 dias
python3 oci_assessment.py --customer "Nome do Cliente" --days 90 --threads 16

# Somente HTML/CSV/JSON (sem PDF e PPTX)
python3 oci_assessment.py --customer "Nome do Cliente" --formats none
```

---

## 7. Regerar os relatórios sem nova coleta

Para corrigir o nome do cliente, gerar formatos que faltaram ou atualizar o layout depois de uma nova versão do script, use o `dados.json` de uma execução anterior. Não há acesso à OCI nesse modo, e o SDK `oci` não é necessário:

```bash
python3 oci_assessment.py --render-only ./oci-assessment-20261123-1619/dados.json --customer "Nome do Cliente"
```

Por padrão os arquivos são reescritos na mesma pasta do `dados.json`. Use `--out <pasta>` para gravar em outro lugar.

> Um `dados.json` gerado por versões anteriores do script não tem custo por recurso. Nesse caso o slide e as tabelas de **DE/PARA de economia** e de **recursos que mais consumiram** são omitidos (o log avisa). Faça uma nova coleta para obtê-los.

### Premissas do DE/PARA de economia

- **DE** é o custo real faturado (Usage API) nos últimos 30 dias dos recursos apontados em cada oportunidade.
- **PARA** é o custo depois da ação recomendada, aplicando a redução de cada categoria definida em `SAVINGS_RULES` no script:

| Categoria | Redução | Ação considerada |
|---|---|---|
| Volume não anexado | 100% | Backup final e exclusão |
| IP público reservado sem uso | 100% | Liberar o IP |
| Instância parada | 100% | Imagem/backup e terminate (inclui boot/block volumes anexados) |
| Instância ociosa | 60% | Desligar fora do horário comercial ou consolidar |
| Bucket sem lifecycle/auto-tiering | 50% | Auto-tiering / Infrequent Access |
| Instância subutilizada | 40% | Rightsizing |
| Shape legado | 20% | Migração para shape Flex atual |

Cada recurso entra uma única vez, na categoria de maior redução. Ajuste os percentuais em `SAVINGS_RULES` conforme a política do cliente e regere com `--render-only`.

---

## 8. Solução de problemas

| Sintoma | Causa provável | O que fazer |
|---|---|---|
| Erro logo no início com `NotAuthorizedOrNotFound` | Usuário sem a policy do passo 3, ou policy fora do compartment root | Conferir o grupo do usuário e a policy no root |
| `Authorization failed` / `401` com `--auth config` | Fingerprint, OCIDs ou `key_file` incorretos no `~/.oci/config` | Copiar de novo o trecho do Console (passo 5.2) e conferir o caminho do `.pem` |
| Coletor como **"parcial"** no Apêndice A | Falta de permissão em parte dos compartments ou serviço não habilitado na região | Revisar a policy. Os controles ligados a esse coletor podem estar subestimados |
| Seção de custos vazia ou `cost: parcial` | Falta `read usage-reports in tenancy` ou limitação da Usage API | Adicionar o statement e rodar de novo |
| `relatorio_*.pdf não gerado: módulo 'reportlab' ausente` | Bibliotecas de relatório não instaladas | `pip3 install --user reportlab python-pptx` e regerar com `--render-only` |
| `SyntaxError` ou `TypeError` ao iniciar | Python abaixo de 3.10 | Usar Python 3.10+ (passo 4.2 ou 5.1) |
| Execução interrompida no Cloud Shell | Sessão desconectou por inatividade | Rodar com `nohup` (passo 4.5) |
| Execução muito lenta | Muitos compartments ou regiões | Aumentar `--threads`, ou limitar com `--regions` / `--compartments` |

---

## 9. Segurança e confidencialidade

- A coleta é somente leitura e usa apenas as permissões do usuário que executa.
- Os arquivos gerados, principalmente `dados.json` e os CSVs, contêm **inventário, nomes de recursos, regras de rede e custos do cliente**. Trate-os como confidenciais e compartilhe apenas por canais aprovados pelo cliente.
- Ao final do trabalho:
  - apague os arquivos do Cloud Shell (passo 4.7) ou da máquina local;
  - remova a API key, se tiver usado a opção B;
  - combine com o cliente se o grupo e a policy `oci-assessment` serão mantidos (para reavaliações periódicas) ou removidos.

---

## 10. Antes de apresentar

Os achados vêm de regras fixas no script (limites e severidades definidos no código) e algumas verificações são heurísticas, como a cobertura de alarmes. Antes de levar os relatórios aos stakeholders:

1. Confira o **Apêndice A** do relatório técnico: coletores "parciais" indicam dados incompletos.
2. Valide com o time do cliente os achados de prioridade **Alta**.
3. Confirme se ferramentas externas (ex.: Dynatrace) cobrem lacunas apontadas no OCI, como APM e monitoração sintética.
4. Ajuste o roadmap conforme a capacidade do time antes de apresentar o plano 30/60/90.
