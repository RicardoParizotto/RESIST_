These are the agents created for SERENE. In RESIST we are using these agents for training simple models in a synchronous manner. 


# SERENE

## Executando o sistema

```bash
python3 run.py [options]
```

Opções disponíveis

--model: modelo a ser treinado ["simple", "cnn", "resnet18"]

--stale: diferença máxima de iteração entre workers

--workers: número de workers no treinamento

--table-cols: número de colunas na tabela de agragação. É também o número de valores de gradiente enviado por pacote

--table-rows: número de linhas na tabela de agregação. Por padrão, é "auto" (calculado de acordo com o número de colunas). Pode ser definido como "keep" (manter o número igual ao padrão) ou definido para um valor inteiro específico

--just-read-pkt: Com essa opção, o sistema não faz a agregação, apenas lê os gradientes dos pacotes

## Exemplo:
```
python3 run.py --workers 4 --stale 0 --model simple --table-rows keep --table-cols 1 --just-read-pkt
```

Nesse modelo, o uso de memória no switch para a tabela (apenas leitura) é de 9940 bytes e a memória necessária para o controle de barreiras é 40 bits.
