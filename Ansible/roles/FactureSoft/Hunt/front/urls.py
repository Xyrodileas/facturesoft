from django.conf.urls import url

from . import views

urlpatterns = [
    url(r'^$', views.overview, name='home'),

    url(r'^tree/(?P<workstation>aff4:\/.\..{16})', views.tree, name='tree'),
    url(r'^json/(?P<workstation>aff4:\/.\..{16})', views.json, name='json'),
    url(r'^json/tree_openport/(?P<workstation>aff4:\/.\..{16})', views.tree_json_with_open_port, name='tree_json_with_open_port'),
    url(r'^json', views.json, name='json'),
    url(r'^tree', views.tree, name='tree'),
    url(r'^workstations', views.overview_workstation, name='workstations'),
    url(r'^csv/sockets/(?P<hunt>H:.{8})', views.socket_csv, name='socket_csv'),
    url(r'^csv/sockets', views.socket_csv, name='socket_csv'),
    url(r'^sockets/(?P<hunt>H:.{8})', views.sockets, name='sockets'),
    url(r'^sockets', views.sockets, name='sockets'),
    url(r'^success', views.upload_hunt_success, name='upload_hunt_success'),
    url(r'^uploadHunt', views.upload_hunt, name='upload_hunt'),
    url(r'^searchProcess', views.heatmap_page, name='heatmap_page'),
    url(r'^entropy', views.entropy, name='entropy'),
    url(r'^hashs', views.hashs, name='hashs'),
    url(r'^persistence', views.persistence, name='persistence'),
    url(r'^workstation/(?P<workstation>aff4:\/.\..{16})', views.overview_workstation, name='workstation'),
]