
# NS.Logging - Biblioteca de Abstração de Logging

Biblioteca interna para fornecer uma camada de abstração configurável sobre o Serilog, permitindo um logging consistente e flexível em aplicações .NET Framework e .NET Core/.NET 8+.

## Funcionalidades

* **Abstração:** As aplicações dependem apenas de `NS.Logging` e `Microsoft.Extensions.Logging.Abstractions`, não diretamente do Serilog.
* **Configurabilidade:** Configuração centralizada via `appsettings.json` da aplicação consumidora.
* **Múltiplos Sinks:** Suporte configurável para diversos destinos (sinks):
    * Console
    * Ficheiro (Rolling)
    * SQL Server (MSSqlServer)
    * RabbitMQ
    * Elasticsearch
* **Enriquecimento Padrão:** Inclui automaticamente informações úteis como:
    * `MachineName`
    * `ThreadId`
    * `ApplicationVersion` (do assembly de entrada)
    * Propriedades do `LogContext` (via `FromLogContext`)
* **Logging Assíncrono:** Os sinks de I/O (File, MSSqlServer, RabbitMQ, Elasticsearch, Console) são configurados por defeito para operar em background para melhor performance.
* **Compatibilidade:** Suporta .NET Framework (via métodos `InitializeFrameworkLogging`/`CreateFrameworkLogger`) e .NET Core/.NET 8+ (via integração com `ILoggingBuilder`/DI).
* **Diagnóstico:** Ativa `SelfLog` do Serilog para a janela de Debug em builds `DEBUG` para facilitar a resolução de problemas internos do logging.

## Instalação / Referência

1.  Adicione uma referência ao projeto `NS.Logging` (ou ao pacote NuGet privado, se criado) na sua aplicação .NET Framework ou .NET Core.
2.  Certifique-se que a sua aplicação final também tem as seguintes referências de pacotes NuGet (necessárias para `Microsoft.Extensions.Configuration` e `ILogger`):
    * `Microsoft.Extensions.Logging.Abstractions`
    * `Microsoft.Extensions.Configuration`
    * `Microsoft.Extensions.Configuration.Json`
    * `Microsoft.Extensions.Configuration.Binder` (para `GetValue`)
    * `Microsoft.Extensions.Configuration.FileExtensions` (se usar `LoadFrameworkConfiguration`)

## Inicialização

### Aplicações .NET Core / .NET 8+ (Ex: `Program.cs`)

Use a integração com `IHostBuilder` ou `WebApplicationBuilder`.

```csharp
using NS.Logging;
using Serilog; // Necessário para Log.CloseAndFlush() no final

// ...
var builder = WebApplication.CreateBuilder(args);

// Configurar Serilog através da nossa biblioteca
builder.Host.ConfigureLogging((context, loggingBuilder) =>
{
    // Passa o ILoggingBuilder e o IConfiguration para a nossa biblioteca
    LoggingConfigurator.Configure(loggingBuilder, context.Configuration);
});
// Alternativa (se usar UseSerilog diretamente):
// builder.Host.UseSerilog((context, services, loggerConfiguration) => {
//     // Aqui teria de replicar a lógica de ConfigureSerilogInternal ou chamá-la de alguma forma
//     // A abordagem com ConfigureLogging é mais limpa para usar a DLL existente.
// });


// ... Restante configuração do builder (serviços, etc.)

var app = builder.Build();

// ... Restante configuração da app

try
{
    Log.Information("Aplicação a iniciar."); // Log estático inicial (opcional)
    app.Run();
}
catch (Exception ex)
{
    Log.Fatal(ex, "Aplicação falhou fatalmente ao iniciar.");
}
finally
{
    Log.CloseAndFlush(); // ESSENCIAL: Garante que todos os logs são escritos antes de sair
}
```

## Aplicações .NET Framework (Ex: `Global.asax.cs` ou `Program.cs`)
Chame `InitializeFrameworkLogging` no início da aplicação.

```csharp

using Microsoft.Extensions.Configuration;
using NS.Logging;
using Serilog; // Para CloseAndFlush

// Em Global.asax (ASP.NET WebForms/MVC)
public class Global : System.Web.HttpApplication
{
    void Application_Start(object sender, EventArgs e)
    {
        // Carregar configuração (usando o helper ou o seu método)
        IConfiguration configuration = LoggingConfigurator.LoadFrameworkConfiguration();
        // Ou: IConfiguration configuration = /* Seu método para obter IConfiguration */;

        // Inicializar o logging
        LoggingConfigurator.InitializeFrameworkLogging(configuration);

        var logger = LoggingConfigurator.CreateFrameworkLogger<Global>();
        logger.LogInformation("Aplicação Framework iniciada.");
    }

     void Application_End(object sender, EventArgs e)
     {
        // CloseAndFlush é chamado automaticamente pelo hook ProcessExit
        var logger = LoggingConfigurator.CreateFrameworkLogger<Global>();
        logger?.LogInformation("Aplicação Framework a terminar.");
     }
}
```
```csharp
// Em Program.cs (WinForms/WPF/Console)
static class Program
{
    [STAThread]
    static void Main()
    {
        IConfiguration configuration = LoggingConfigurator.LoadFrameworkConfiguration();
        LoggingConfigurator.InitializeFrameworkLogging(configuration);
        var logger = LoggingConfigurator.CreateFrameworkLogger<Program>();

        try
        {
             logger.LogInformation("Aplicação Desktop iniciada.");
             // Application.Run(...) ou outra lógica principal
        }
        catch(Exception ex)
        {
             logger.LogError(ex, "Erro não tratado na aplicação.");
             // Tratar/mostrar erro ao utilizador
        }
        finally
        {
             // CloseAndFlush chamado automaticamente
              logger.LogInformation("Aplicação Desktop a terminar.");
        }
    }
}
```

## Configuração (appsettings.json)
A biblioteca lê a sua configuração de um ficheiro `appsettings.json` (e `appsettings.{Environment}.json`) na aplicação final. Abaixo estão as chaves de configuração suportadas:

#### Secção Serilog
| Chave |	Descrição |	Exemplo |	Obrigatório |
|---|---|---|---|
| `MinimumLevel:Default`  |	Nível de log mínimo global (Verbose, Debug, Information, Warning, Error, Fatal) |	`"Information"` |	Sim |
| `MinimumLevel:Override:{Namespace}` |	Sobrescreve o nível mínimo para um namespace específico |	`"Microsoft": "Warning"` |	Não |
| `Properties:{Nome}` |	Adiciona uma propriedade global a todos os eventos de log |	`"Application": "MyApp"` |	Não

#### Secção `ConnectionStrings`
| Chave |	Descrição |	Exemplo |	Obrigatório |
|---|---|---|---|
|`LogDatabase` |	Connection String para o sink SQL Server |	`"Server=...;Database=...;User ID=...;Password=...;"` |	Se Sink DB ativo |

#### Secção `LoggingOutputTemplates`
| Chave |	Descrição |	Exemplo (Default) |	Obrigatório |
|---|---|---|---|
| `Console` |	Template para o sink Console |	`"[{Timestamp:HH:mm:ss} {Level:u3}] ({SourceContext}) {Message:lj}{NewLine}{Exception}"` |	Não |
| `File` |	Template para o sink Ficheiro |	`"{Timestamp:yyyy-MM-dd HH:mm:ss.fff zzz} [{Level:u3}] {Properties:j} {Message:lj}{NewLine}{Exception}"` |	Não |

#### Secção `LoggingSinkLevels`
| Chave |	Descrição |	Exemplo |	Obrigatório |
|---|---|---|---|
| `Console` |	Nível mínimo para o sink Console |	`"Information"` |	Não |
| `File` |	Nível mínimo para o sink Ficheiro |	`"Information"` |	Não |
| `Database` |	Nível mínimo para o sink SQL Server |	`"Warning"` |	Não |
| `RabbitMQ` |	Nível mínimo para o sink RabbitMQ (levelSwitch) |	`"Information"` |	Não |
| `Elasticsearch` |	Nível mínimo para o sink Elasticsearch |	`"Information"` |	Não |

#### Secção `LoggingSinkSettings`
(Nota: Para muitos parâmetros opcionais, se a chave não for fornecida no JSON, o código C# usa `null` ou `false`/`0` ao chamar o método do Sink, o que geralmente faz com que o Sink utilize o seu próprio valor default interno. Os defaults listados abaixo são os aplicados pelo código C# _antes_ de chamar o Sink, ou o default lógico do sink).
| Chave | Descrição |	Exemplo | Obrigatório |
|------|------|------|------|
| `Console:Enabled` |	Ativa/Desativa o sink Console (boolean)	| `true` |	Não (Default true) |
| `File:Enabled` |	Ativa/Desativa o sink Ficheiro (boolean) |	`true` |	Não (Default true) |
| `File:Path` |	Caminho do ficheiro de log |	`"Logs/MyApp-.log"` |	Não (Default existe) |
| `File:RetainedFileCountLimit` |	Nº de ficheiros a manter (integer) |	`7` |	Não (Default 7) |
| `SQLServer:Enabled` |	Ativa/Desativa o sink SQL Server (boolean) |	`true` |	Não (Default true) |
| `Database:TableName` |	Nome da tabela no SQL Server |	`"Logs"` |	Não (Default "Logs") |
| `Database:AutoCreateSqlTable` |	Tenta criar a tabela SQL se não existir (boolean) |	`true` |	Não (Default true) |
| `RabbitMQ:Enabled` |	Ativa/Desativa o sink RabbitMQ (boolean) |	`false` |	Não (Default false) |
| `RabbitMQ:Hostname` |	Hostname(s) do servidor RabbitMQ (string, separados por vírgula) |	`"localhost" ou "srv1,srv2"` |	Sim (se ativo) |
| `RabbitMQ:Port` |	Porta AMQP (integer) |	`5672` |	Não (Default 0 -> usa default AMQP) |
| `RabbitMQ:Username` |	Utilizador RabbitMQ |	`"guest"` |	Não (Default "") |
| `RabbitMQ:Password` |	Password RabbitMQ (MANTER SEGURO!) |	`"guest"` |	Não (Default "") |
| `RabbitMQ:VHost` |	Virtual Host RabbitMQ |	`"/"` |	Não (Default null) |
| `RabbitMQ:Exchange` |	Nome da Exchange |	`"logs-exchange"` |	Não (Default null) |
| `RabbitMQ:ExchangeType` |	Tipo de Exchange (string: fanout, direct, topic, headers) |	`"fanout"` |	Não (Default null -> implica Fanout) |
| `RabbitMQ:DeliveryMode` |	Modo de entrega (string: Durable, NonDurable) |	`"Durable"` |	Não (Default NonDurable) |
| `RabbitMQ:RoutingKey` |	Routing Key |	`"log.info"` |	Não (Default null)v
| `RabbitMQ:ClientProvidedName` |	Nome da conexão no RabbitMQ (string) |	`"MyAppLogger"` |	Não (Default null) |
| `RabbitMQ:Heartbeat` |	Intervalo de heartbeat em segundos (integer) |	`60` |	Não (Default 0) |
| `RabbitMQ:Ssl:Enabled` |	Ativa SSL/TLS (boolean) |	`false` |	Não (Default false) |
| `RabbitMQ:Ssl:ServerName` |	Nome do servidor no certificado TLS (string) |	`"rabbitmq.mydomain.com"` |	Não (Default null) |
 |`RabbitMQ:Ssl:Version` |	Versão TLS (string: Tls, Tls11, Tls12, Tls13) |	`"Tls12"` |	Não (Default None) |
| `RabbitMQ:Ssl:AcceptablePolicyErrors` |	Erros de política TLS aceitáveis (string: None, RemoteCertificateNameMismatch, ...) |	`"None"` |	Não (Default None) |
| `RabbitMQ:Ssl:CheckCertificateRevocation` |	Verificar revogação de certificado (boolean) |	`false` |	Não (Default false) |
| `RabbitMQ:BatchPostingLimit` |	Nº máximo de eventos por lote (integer) |	`50` |	Não (Default 50) |
| `RabbitMQ:BufferingTimeLimitSeconds` |	Intervalo entre lotes em segundos (double/integer) |	`2` |	Não (Default 0 -> usa default sink) |
| `RabbitMQ:QueueLimit` |	Limite da fila de batching interna (integer) |	`10000` |	Não (Default null) |
| `RabbitMQ:AutoCreateExchange` |	Tenta criar exchange se não existir (boolean) |	`true` |	Não (Default false) |
| `RabbitMQ:MaxChannels` |	Nº máximo de canais AMQP (integer) |	`10` |	Não (Default 10) |
| `RabbitMQ:EmitEventFailure` |	Ação em caso de falha de envio (string: WriteToSelfLog, ThrowException, Ignore) |	`"WriteToSelfLog"` |	Não (Default WriteToSelfLog) |
| `Elasticsearch:Enabled` |	Ativa/Desativa o sink Elasticsearch (boolean) |	`false` |	Não (Default false) |
| `Elasticsearch:NodeUris` |	URI(s) dos nós Elasticsearch (string, separados por ; ou ,) |	`"http://localhost:9200"` |	Sim (se ativo) |
| `Elasticsearch:BootstrapMethod` |	Método de ligação (string: Failure, Static, Sniffing) |	`"Failure"` |	Não (Default Failure) |
| `Elasticsearch:UseSniffing` |	Usar sniffing (boolean) |	`false` |	Não (Default false) |
| `Elasticsearch:DataStreamName` |	Nome do Data Stream (string) |	`"logs-myapp-generic"` |	Não (Default null) |
| `Elasticsearch:IlmPolicyName` |	Nome da política ILM (string) |	`"my-ilm-policy"` |	Não | (Default null) |
| `Elasticsearch:Authentication:Type` |	Tipo de autenticação (string: None, Basic, ApiKey, CloudId) |	`"None"` |	Não (Default None) |
| `Elasticsearch:Authentication:Username` |	Utilizador (para Basic/CloudId) |	`"elastic"` |	Não |
| `Elasticsearch:Authentication:Password` |	Password (MANTER SEGURO!) |	`"changeme"` |	Não |
| `Elasticsearch:Authentication:ApiKeyId` |	ID da API Key (para ApiKey/CloudId) |	`"my_key_id"` |	Não |
| `Elasticsearch:Authentication:ApiKey` |	Segredo da API Key (MANTER SEGURO!) |	`"my_key_secret"` |	Não |
| `Elasticsearch:Authentication:CloudId` |	Cloud ID (para CloudId) |	`"my_cloud_deployment:..."` |	Não |


## IMPORTANTE: Segurança de Credenciais

NUNCA coloque passwords, API keys, ou connection strings completas diretamente no `appsettings.json` em ambientes de produção. Utilize mecanismos seguros como Azure Key Vault, AWS Secrets Manager, Variáveis de Ambiente, User Secrets (desenvolvimento), ou outras ferramentas de gestão de segredos. Configure o `IConfiguration` da sua aplicação para ler destas fontes seguras.

## Utilização
Obtenha uma instância de `ILogger` através de Injeção de Dependência (preferencial em .NET Core) ou usando os métodos `CreateFrameworkLogger` (em .NET Framework).

```csharp
using Microsoft.Extensions.Logging;

public class MeuServico
{
    private readonly ILogger<MeuServico> _logger;

    // Exemplo .NET Core com DI
    public MeuServico(ILogger<MeuServico> logger)
    {
        _logger = logger;
    }

    // Exemplo .NET Framework
    // private readonly ILogger _logger = NS.Logging.LoggingConfigurator.CreateFrameworkLogger<MeuServico>();

    public void Executar(int id, string nome)
    {
        _logger.LogInformation("A iniciar execução para ID: {ResourceId} com Nome: {ResourceName}", id, nome);

        try
        {
            using (_logger.BeginScope("OperacaoComplexa {CorrelationId}", Guid.NewGuid())) // Inicia um escopo lógico
            {
                 _logger.LogDebug("A processar passo 1...");
                 // ... lógica ...
                 if (nome == "ERRO") throw new InvalidOperationException("Nome inválido encontrado.");
                 _logger.LogInformation("Passo 1 concluído.");
            } // Fim do escopo

             _logger.LogWarning("Execução concluída com um aviso para ID: {ResourceId}", id);
        }
        catch(Exception ex)
        {
             _logger.LogError(ex, "Falha na execução para ID: {ResourceId}. Nome: {ResourceName}", id, nome);
             // Reter ou tratar a exceção conforme necessário
        }
    }
}
```
## Principais Práticas:

* Use Logging Estruturado: Utilize placeholders `{NomeDaPropriedade}` nas suas mensagens em vez de concatenação de strings. Isto permite pesquisar e filtrar logs mais facilmente nos sinks que o suportam (BD, Elasticsearch, etc.).
* Use Níveis de Log Adequados: Log Information para eventos normais, Warning para situações inesperadas mas recuperáveis, Error/Critical para falhas. Use Debug/Verbose para informação detalhada útil apenas durante o desenvolvimento/diagnóstico.
* Use Escopos (`BeginScope`): Agrupe logs relacionados a uma operação ou pedido específico para facilitar o rastreamento.

## Troubleshooting
* Logs não aparecem: Verifique os níveis mínimos configurados (global e por sink), as flags `Enabled` para cada sink, e os caminhos/connection strings/URLs.
* Erros internos do Serilog: Verifique o output da janela de Debug no Visual Studio (se `SelfLog` estiver ativo em DEBUG) para mensagens de erro do próprio Serilog (ex: falha ao ligar a um sink).