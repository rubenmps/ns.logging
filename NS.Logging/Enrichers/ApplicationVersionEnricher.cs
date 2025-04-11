using Serilog.Core;
using Serilog.Events;
using System;
using System.Collections.Generic;
using System.Reflection;
using System.Text;

namespace NS.Logging.Enrichers
{
    public class ApplicationVersionEnricher : ILogEventEnricher
    {
        private string _appVersion;

        public void Enrich(LogEvent logEvent, ILogEventPropertyFactory propertyFactory)
        {
            // Cache a versão para não a obter a cada log
            _appVersion ??= Assembly.GetEntryAssembly()?.GetName().Version?.ToString() ?? "N/A";

            // Cria a propriedade a adicionar ao log
            var appVersionProperty = propertyFactory.CreateProperty("AppVersion", _appVersion);
            logEvent.AddPropertyIfAbsent(appVersionProperty);
        }
    }

    public static class LoggingEnricherExtensions
    {
        public static Serilog.LoggerConfiguration WithApplicationVersion(this Serilog.Configuration.LoggerEnrichmentConfiguration enrich)
        {
            return enrich.With<ApplicationVersionEnricher>();
        }
    }
}
