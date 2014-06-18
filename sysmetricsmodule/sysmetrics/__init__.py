from routes.route import Route

# controllers routes that this module provides
# Route(name, uri, controller name)
ControllerRoutes = [Route(None, "/{action}", controller="sysmetrics")]
# controller class to controller name map {controller name: (controller module, controller class)}
ControllerClass =  {"sysmetrics": ("sysmetrics.sysmetrics", 'SysMetricsController')}