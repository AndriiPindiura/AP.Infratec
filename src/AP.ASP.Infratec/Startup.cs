using Microsoft.AspNet.Builder;
using Microsoft.Framework.DependencyInjection;

namespace AP.ASP.Infratec
{
    public class Startup
    {
        // For more information on how to configure your application, visit http://go.microsoft.com/fwlink/?LinkID=398940
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddMvcCore();
            //services.AddMvc();
        }

        public void Configure(IApplicationBuilder app)
        {
            //var loggerFactory = new LoggerFactory().CreateLogger(typeof(Program).FullName);

            /*RouteCollection routes = new RouteCollection();
            routes.Add(new {  })*/
            app.UseMvc(routes =>
            {
                routes.MapRoute(
                    name: "default",
                    template: "{controller}/{action}/{id?}"/*,
                    defaults: new { controller = "Home", action = "Index" }*/);
            });


            /*app.Run(async (context) =>
            {
                await context.Response.WriteAsync("Hello World!");
            });*/
        }
    }
}
