using Elastic.Ingest.Elasticsearch;
using Elastic.Serilog.Sinks;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using NS.Logging.Enrichers;
using Serilog;
using Serilog.Events;
using Serilog.Sinks.MSSqlServer;
using Serilog.Sinks.RabbitMQ;
using System;
using System.Linq;
using System.Net.Security;
using System.Security.Authentication;
using System.Threading.Channels;

namespace NS.Logging
{
    /// <summary>
    /// Classe estática responsável pela configuração centralizada do Serilog
    /// para aplicações .NET Core e .NET Framework.
    /// </summary>
    public static class LoggingConfigurator
    {
        private static ILoggerFactory _loggerFactory;
        private static readonly object _lock = new object(); // Lock para inicialização thread-safe no Framework

        /// <summary>
        /// Configura o pipeline interno do Serilog com base na configuração fornecida.
        /// Adiciona Sinks, Enrichers e lê níveis de log.
        /// </summary>
        /// <param name="configuration">A <see cref="IConfiguration"/> da aplicação.</param>
        private static void ConfigureSerilogInternal(IConfiguration configuration)
        {
#if DEBUG 
            // Ativa o log de diagnóstico interno do Serilog para a janela de Debug.
            // Útil para detetar problemas na configuração ou nos sinks.
            Serilog.Debugging.SelfLog.Enable(msg => System.Diagnostics.Debug.WriteLine($"SERILOG INTERNAL ERROR: {msg}"));
#endif

            // Configura Serilog
            var loggerConfiguration = new LoggerConfiguration()
                .ReadFrom.Configuration(configuration)
                // Enrichers Padrão: Adicionam contexto útil a todos os eventos de log.
                .Enrich.FromLogContext() // Permite adicionar propriedades contextuais com LogContext.PushProperty().
                .Enrich.WithMachineName() // Adiciona o nome da máquina onde a aplicação corre.
                .Enrich.WithThreadId() // Adiciona o ID da thread que gerou o log.
                // Enricher Personalizado:
                .Enrich.WithApplicationVersion(); // Adiciona a versão do Assembly de entrada.

            // Configuração dos Sinks individualmente, permitindo ativação via appsettings.json

            // --- Sink: Console ---
            if (configuration.GetValue<bool?>("LoggingSinkSettings:Console:Enabled") ?? true)
            {
                // Escreve para a Console de forma assíncrona.
                loggerConfiguration.WriteTo.Async(a => a.Console(
                     outputTemplate: configuration.GetValue<string>("LoggingOutputTemplates:Console", // Usa template do JSON ou um default.
                                   "[{Timestamp:HH:mm:ss} {Level:u3}] ({SourceContext}) {Message:lj}{NewLine}{Exception}"),
                     restrictedToMinimumLevel: configuration.GetValue<LogEventLevel?>("LoggingSinkLevels:Console") ?? LogEventLevel.Information // Nível do appsettings ou default
                 ));
            }

            // --- Sink: Ficheiro ---
            if (configuration.GetValue<bool?>("LoggingSinkSettings:File:Enabled") ?? true)
            {
                // Escreve para um ficheiro de forma assíncrona, com rotação diária.
                loggerConfiguration.WriteTo.Async(a => a.File(
                    path: configuration.GetValue<string>("LoggingSinkSettings:File:Path", "Logs/DefaultLog-.log"), // Path do appsettings ou default
                    rollingInterval: RollingInterval.Day,
                    outputTemplate: configuration.GetValue<string>("LoggingOutputTemplates:File",
                                   "{Timestamp:yyyy-MM-dd HH:mm:ss.fff zzz} [{Level:u3}] {Properties:j} {Message:lj}{NewLine}{Exception}"),
                     restrictedToMinimumLevel: configuration.GetValue<LogEventLevel?>("LoggingSinkLevels:File") ?? LogEventLevel.Information, // Nível do appsettings ou default
                     retainedFileCountLimit: configuration.GetValue<int?>("LoggingSinkSettings:File:RetainedFileCountLimit", 7) // Retenção do appsettings ou default
                 ));
            }

            // --- Sink: SQL Server ---
            if (configuration.GetValue<bool?>("LoggingSinkSettings:SQLServer:Enabled") ?? true) // Ativo por defeito
            {
                string dbConnectionString = configuration.GetConnectionString("LogDatabase");
                // Apenas configura o sink se a connection string for fornecida.
                if (!string.IsNullOrEmpty(dbConnectionString))
                {
                    // Escreve para SQL Server de forma assíncrona.
                    loggerConfiguration.WriteTo.Async(a => a.MSSqlServer(
                        connectionString: dbConnectionString,
                        sinkOptions: new MSSqlServerSinkOptions // Opções específicas do sink SQL.
                        {
                            TableName = configuration.GetValue<string>("LoggingSinkSettings:Database:TableName", "Logs"), // Nome da tabela.
                            AutoCreateSqlTable = configuration.GetValue<bool?>("LoggingSinkSettings:Database:AutoCreateSqlTable", true) ?? true, // Cria a tabela se não existir.
                        },
                        restrictedToMinimumLevel: configuration.GetValue<LogEventLevel?>("LoggingSinkLevels:Database") ?? LogEventLevel.Warning // Nível mínimo (geralmente mais restrito para BD).
                    ));
                }
                else if (configuration.GetValue<bool?>("LoggingSinkSettings:SQLServer:Enabled") ?? false) // Loga aviso se estava ativo mas sem connection string
                {
                    Serilog.Debugging.SelfLog.WriteLine("SQLServer sink está ativo ('LoggingSinkSettings:SQLServer:Enabled' = true) mas a ConnectionString 'LogDatabase' não foi fornecida.");
                }
            }

            // --- Sink: RabbitMQ ---
            if (configuration.GetValue<bool?>("LoggingSinkSettings:RabbitMQ:Enabled") ?? false)
            {
                // Lê os parâmetros de configuração para o RabbitMQ.
                var hostnames = configuration.GetValue<string>("LoggingSinkSettings:RabbitMQ:Hostname")?
                                    .Split(new[] { ',' }, StringSplitOptions.RemoveEmptyEntries)
                                    .Select(h => h.Trim())
                                    .ToArray() ?? Array.Empty<string>(); // Precisa ser string[]
                var username = configuration.GetValue<string>("LoggingSinkSettings:RabbitMQ:Username") ?? string.Empty;
                var password = configuration.GetValue<string>("LoggingSinkSettings:RabbitMQ:Password") ?? string.Empty;
                var exchange = configuration.GetValue<string>("LoggingSinkSettings:RabbitMQ:Exchange");
                var exchangeType = configuration.GetValue<string>("LoggingSinkSettings:RabbitMQ:ExchangeType");
                var deliveryModeString = configuration.GetValue<string>("LoggingSinkSettings:RabbitMQ:DeliveryMode") ?? "NonDurable";
                var deliveryMode = deliveryModeString.Equals("Durable", StringComparison.OrdinalIgnoreCase) ? RabbitMQDeliveryMode.Durable : RabbitMQDeliveryMode.NonDurable;
                var routingKey = configuration.GetValue<string>("LoggingSinkSettings:RabbitMQ:RoutingKey");
                var port = configuration.GetValue<int?>("LoggingSinkSettings:RabbitMQ:Port") ?? 0;
                var vHost = configuration.GetValue<string>("LoggingSinkSettings:RabbitMQ:VHost");
                var clientProvidedName = configuration.GetValue<string>("LoggingSinkSettings:RabbitMQ:ClientProvidedName");
                var heartbeat = (ushort)(configuration.GetValue<int?>("LoggingSinkSettings:RabbitMQ:Heartbeat") ?? 0);
                // Configurações SSL
                var sslEnabled = configuration.GetValue<bool?>("LoggingSinkSettings:RabbitMQ:Ssl:Enabled") ?? false;
                var sslServerName = configuration.GetValue<string>("LoggingSinkSettings:RabbitMQ:Ssl:ServerName");
                var sslVersionString = configuration.GetValue<string>("LoggingSinkSettings:RabbitMQ:Ssl:Version");
                SslProtocols sslVersion = SslProtocols.None;
                if (Enum.TryParse<SslProtocols>(sslVersionString, ignoreCase: true, out var parsedSslVersion)) { sslVersion = parsedSslVersion; }
                var sslAcceptablePolicyErrorsString = configuration.GetValue<string>("LoggingSinkSettings:RabbitMQ:Ssl:AcceptablePolicyErrors");
                SslPolicyErrors sslAcceptablePolicyErrors = SslPolicyErrors.None; // Default na assinatura
                if (Enum.TryParse<SslPolicyErrors>(sslAcceptablePolicyErrorsString, ignoreCase: true, out var parsedSslErrors)) { sslAcceptablePolicyErrors = parsedSslErrors; }
                var sslCheckCertificateRevocation = configuration.GetValue<bool?>("LoggingSinkSettings:RabbitMQ:Ssl:CheckCertificateRevocation") ?? false; // Default false
                // Configurações de Batching e Queue
                var batchPostingLimit = configuration.GetValue<int?>("LoggingSinkSettings:RabbitMQ:BatchPostingLimit"); // Usará default interno do sink se null
                var bufferingTimeLimitSeconds = configuration.GetValue<double?>("LoggingSinkSettings:RabbitMQ:BufferingTimeLimitSeconds"); // Ler como double/int
                var bufferingTimeLimit = bufferingTimeLimitSeconds.HasValue ? TimeSpan.FromSeconds(bufferingTimeLimitSeconds.Value) : default(TimeSpan); // Default TimeSpan.Zero na assinatura
                var queueLimit = configuration.GetValue<int?>("LoggingSinkSettings:RabbitMQ:QueueLimit"); // Default null
                // Outras configs
                var autoCreateExchange = configuration.GetValue<bool?>("LoggingSinkSettings:RabbitMQ:AutoCreateExchange") ?? false; // Default false
                var maxChannels = configuration.GetValue<int?>("LoggingSinkSettings:RabbitMQ:MaxChannels"); // Usará default interno se null
                var levelSwitchString = configuration.GetValue<string>("LoggingSinkSettings:RabbitMQ:MinimumLevel") ?? "Verbose"; // Usar a chave que definimos antes, default Verbose
                LogEventLevel levelSwitch = LogEventLevel.Verbose; // Default da assinatura
                if (Enum.TryParse<LogEventLevel>(levelSwitchString, ignoreCase: true, out var parsedLevel)) { levelSwitch = parsedLevel; }
                var emitEventFailureString = configuration.GetValue<string>("LoggingSinkSettings:RabbitMQ:EmitEventFailure"); // Default WriteToSelfLog na assinatura

                EmitEventFailureHandling emitEventFailure = EmitEventFailureHandling.WriteToSelfLog;
                if (Enum.TryParse<EmitEventFailureHandling>(emitEventFailureString, ignoreCase: true, out var parsedFailureHandling)) { emitEventFailure = parsedFailureHandling; }

                // Apenas configura se houver hostnames definidos.
                if (hostnames.Length > 0)
                {
                    // Escreve para RabbitMQ de forma assíncrona, usando a sobrecarga com múltiplos parâmetros.
                    loggerConfiguration.WriteTo.Async(a => a.RabbitMQ(
                        hostnames: hostnames,
                        username: username,
                        password: password,
                        exchange: exchange,
                        exchangeType: exchangeType,
                        deliveryMode: deliveryMode,
                        routingKey: routingKey,
                        port: port,
                        vHost: vHost,
                        clientProvidedName: clientProvidedName,
                        heartbeat: heartbeat,
                        sslEnabled: sslEnabled,
                        sslServerName: sslServerName,
                        sslVersion: sslVersion,
                        sslAcceptablePolicyErrors: sslAcceptablePolicyErrors,
                        sslCheckCertificateRevocation: sslCheckCertificateRevocation,
                        batchPostingLimit: batchPostingLimit ?? 50,
                        bufferingTimeLimit: bufferingTimeLimit,
                        queueLimit: queueLimit,
                        autoCreateExchange: autoCreateExchange,
                        maxChannels: maxChannels ?? 10,
                        levelSwitch: levelSwitch, 
                        emitEventFailure: emitEventFailure
                    ));
                }
                else
                {
                    Serilog.Debugging.SelfLog.WriteLine("RabbitMQ sink está ativo ('LoggingSinkSettings:RabbitMQ:Enabled' = true) mas 'LoggingSinkSettings:RabbitMQ:Hostname' não foi fornecido.");
                }
            }

            // --- Sink: Elasticsearch ---
            if (configuration.GetValue<bool?>("LoggingSinkSettings:Elasticsearch:Enabled") ?? false)
            {
                string elasticSearchNodes = configuration.GetValue<string>("LoggingSinkSettings:Elasticsearch:NodeUris");
                // Apenas configura se houver URIs de nós definidos.
                if (!string.IsNullOrEmpty(elasticSearchNodes))
                {
                    var nodeUris = elasticSearchNodes.Split(new[] { ';', ',' }, StringSplitOptions.RemoveEmptyEntries)
                                           .Select(uri => new Uri(uri.Trim()))
                                           .ToList();

                    // Lê os parâmetros de configuração para Elasticsearch.
                    var bootstrapMethodString = configuration.GetValue<string>("LoggingSinkSettings:Elasticsearch:BootstrapMethod") ?? "Failure";
                    BootstrapMethod bootstrapMethod = BootstrapMethod.Failure; // Default
                    Enum.TryParse<BootstrapMethod>(bootstrapMethodString, ignoreCase: true, out bootstrapMethod);
                    bool useSniffing = configuration.GetValue<bool?>("LoggingSinkSettings:Elasticsearch:UseSniffing") ?? false;
                    string dataStream = configuration.GetValue<string>("LoggingSinkSettings:Elasticsearch:DataStreamName");
                    string ilmPolicy = configuration.GetValue<string>("LoggingSinkSettings:Elasticsearch:IlmPolicyName");

                    // Autenticação
                    string apiKey = configuration.GetValue<string>("LoggingSinkSettings:Elasticsearch:Authentication:ApiKey");
                    string username = configuration.GetValue<string>("LoggingSinkSettings:Elasticsearch:Authentication:Username");
                    string password = configuration.GetValue<string>("LoggingSinkSettings:Elasticsearch:Authentication:Password");
                    // Flags de Inclusão
                    bool? includeHost = configuration.GetValue<bool?>("LoggingSinkSettings:Elasticsearch:IncludeHost");
                    bool? includeActivity = configuration.GetValue<bool?>("LoggingSinkSettings:Elasticsearch:IncludeActivity");
                    // Buffering / Concorrência
                    int? maxRetries = configuration.GetValue<int?>("LoggingSinkSettings:Elasticsearch:MaxRetries");
                    int? maxConcurrency = configuration.GetValue<int?>("LoggingSinkSettings:Elasticsearch:MaxConcurrency");
                    int? maxInflight = configuration.GetValue<int?>("LoggingSinkSettings:Elasticsearch:MaxInflight");
                    int? maxExportSize = configuration.GetValue<int?>("LoggingSinkSettings:Elasticsearch:MaxExportSize");
                    TimeSpan? maxLifeTime = configuration.GetValue<int?>(("LoggingSinkSettings:Elasticsearch:MaxLifeTimeSeconds")) != null ?
                                                TimeSpan.FromSeconds(configuration.GetValue<int>("LoggingSinkSettings:Elasticsearch:MaxLifeTimeSeconds")) :
                                                (TimeSpan?)null;
                    var fullModeString = configuration.GetValue<string>("LoggingSinkSettings:Elasticsearch:FullMode");
                    BoundedChannelFullMode? fullMode = null;
                    if (Enum.TryParse<BoundedChannelFullMode>(fullModeString, ignoreCase: true, out var parsedMode))
                    {
                        fullMode = parsedMode;
                    }

                    // Proxy
                    string proxyUriString = configuration.GetValue<string>("LoggingSinkSettings:Elasticsearch:Proxy:Uri");
                    Uri proxy = !string.IsNullOrEmpty(proxyUriString) ? new Uri(proxyUriString) : null;
                    string proxyUsername = configuration.GetValue<string>("LoggingSinkSettings:Elasticsearch:Proxy:Username");
                    string proxyPassword = configuration.GetValue<string>("LoggingSinkSettings:Elasticsearch:Proxy:Password");
                    // Proxy
                    string fingerprint = configuration.GetValue<string>("LoggingSinkSettings:Elasticsearch:Fingerprint");
                    bool debugMode = configuration.GetValue<bool?>("LoggingSinkSettings:Elasticsearch:DebugMode") ?? false;
                    var minimumLevel = configuration.GetValue<LogEventLevel?>("LoggingSinkSettings:Elasticsearch:MinimumLevel") ?? LogEventLevel.Information;

                    // Escreve para Elasticsearch de forma assíncrona, usando a sobrecarga apropriada.
                    // Nota: A assinatura exata pode variar ligeiramente entre versões do Elastic.Serilog.Sinks.
                    // Este exemplo assume a assinatura encontrada anteriormente.
                    loggerConfiguration.WriteTo.Async(a => a.Elasticsearch(
                        bootstrapMethod: bootstrapMethod,
                        nodes: nodeUris,
                        useSniffing: useSniffing,
                        dataStream: dataStream,
                        ilmPolicy: ilmPolicy,
                        apiKey: apiKey,
                        username: username,
                        password: password,
                        includeHost: includeHost,
                        includeActivity: includeActivity,
                        maxRetries: maxRetries,
                        maxConcurrency: maxConcurrency,
                        maxInflight: maxInflight,
                        maxExportSize: maxExportSize,
                        maxLifeTime: maxLifeTime,
                        fullMode: fullMode,
                        proxy: proxy,
                        proxyUsername: proxyUsername,
                        proxyPassword: proxyPassword,
                        fingerprint: fingerprint,
                        debugMode: debugMode,
                        restrictedToMinimumLevel: minimumLevel
                    ));
                }
                else
                {
                    Serilog.Debugging.SelfLog.WriteLine("Elasticsearch sink está ativo ('LoggingSinkSettings:Elasticsearch:Enabled' = true) mas 'LoggingSinkSettings:Elasticsearch:NodeUris' não foi fornecido.");
                }
            }

            // Finaliza a configuração e cria o Logger estático principal.
            Log.Logger = loggerConfiguration.CreateLogger();
        }

        /// <summary>
        /// Configura o logging para uma aplicação .NET Core (ou mais recente)
        /// usando o pipeline de Injeção de Dependência.
        /// </summary>
        /// <param name="loggingBuilder">O <see cref="ILoggingBuilder"/> fornecido pelo Host.</param>
        /// <param name="configuration">A <see cref="IConfiguration"/> da aplicação.</param>
        /// <returns>O <see cref="ILoggingBuilder"/> configurado.</returns>
        public static ILoggingBuilder Configure(ILoggingBuilder loggingBuilder, IConfiguration configuration)
        {
            loggingBuilder.ClearProviders(); // Limpa providers padrão
            ConfigureSerilogInternal(configuration); // Chama a configuração interna
            loggingBuilder.AddSerilog(dispose: true); // Adiciona o Serilog configurado

            // Cria a factory para possível uso posterior (ex: acesso estático ou .NET Framework)
            // Garante que _loggerFactory é inicializada aqui também.
            lock (_lock)
            {
                _loggerFactory ??= new LoggerFactory().AddSerilog(Log.Logger);
            }

            return loggingBuilder;
        }

        /// <summary>
        /// Inicializa o logging para aplicações .NET Framework ou cenários sem DI.
        /// Deve ser chamado uma única vez no arranque da aplicação.
        /// </summary>
        /// <param name="configuration">A <see cref="IConfiguration"/> da aplicação.</param>
        public static void InitializeFrameworkLogging(IConfiguration configuration)
        {
            // Usa lock para garantir inicialização única em ambientes multi-threaded.
            if (_loggerFactory == null)
            {
                lock (_lock)
                {
                    if (_loggerFactory == null)
                    {
                        ConfigureSerilogInternal(configuration);
                        // Cria a factory que será usada para obter loggers manualmente.
                        _loggerFactory = new LoggerFactory().AddSerilog(Log.Logger);
                        // Garante que os logs em buffer são escritos ao fechar a aplicação.
                        AppDomain.CurrentDomain.ProcessExit += (s, e) => Log.CloseAndFlush();
                    }
                }
            }
        }

        /// <summary>
        /// Obtém uma instância de <see cref="ILogger"/> para usar em aplicações .NET Framework.
        /// Requer que <see cref="InitializeFrameworkLogging"/> tenha sido chamado primeiro.
        /// </summary>
        /// <typeparam name="T">O tipo (geralmente a classe) para o qual o logger será criado (usado como categoria).</typeparam>
        /// <returns>Uma instância de <see cref="ILogger"/>.</returns>
        /// <exception cref="InvalidOperationException">Se o logging não foi inicializado.</exception>
        public static Microsoft.Extensions.Logging.ILogger CreateFrameworkLogger<T>()
        {
            if (_loggerFactory == null)
            {
                // Considerar lançar exceção ou inicializar com config padrão
                throw new InvalidOperationException("Logging não inicializado. Chame InitializeFrameworkLogging primeiro.");
            }
            return _loggerFactory.CreateLogger<T>();
        }

        /// <summary>
        /// Obtém uma instância de <see cref="ILogger"/> para usar em aplicações .NET Framework.
        /// Requer que <see cref="InitializeFrameworkLogging"/> tenha sido chamado primeiro.
        /// </summary>
        /// <param name="categoryName">O nome da categoria para o logger.</param>
        /// <returns>Uma instância de <see cref="ILogger"/>.</returns>
        /// <exception cref="InvalidOperationException">Se o logging não foi inicializado.</exception>
        public static Microsoft.Extensions.Logging.ILogger CreateFrameworkLogger(string categoryName)
        {
            if (_loggerFactory == null)
            {
                throw new InvalidOperationException("Logging não inicializado. Chame InitializeFrameworkLogging primeiro.");
            }
            return _loggerFactory.CreateLogger(categoryName);
        }

        /// <summary>
        /// Helper para carregar a configuração de ficheiros appsettings.json numa aplicação .NET Framework.
        /// Procura por appsettings.json e appsettings.{Environment}.json.
        /// </summary>
        /// <returns>Uma instância de <see cref="IConfiguration"/>.</returns>
        public static IConfiguration LoadFrameworkConfiguration()
        {
            var builder = new ConfigurationBuilder()
               .SetBasePath(AppDomain.CurrentDomain.BaseDirectory)
               // Adiciona o ficheiro base. Opcional=false garante que ele existe. ReloadOnChange recarrega se o ficheiro mudar.
               .AddJsonFile("appsettings.json", optional: false, reloadOnChange: true)
               // Adiciona o ficheiro específico do ambiente. Opcional=true permite que ele não exista.
               .AddJsonFile($"appsettings.{Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT") ?? "Production"}.json", optional: true);

            return builder.Build();
        }
    }
}