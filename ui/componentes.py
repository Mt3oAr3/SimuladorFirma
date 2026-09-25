"""Piezas visuales reutilizables: explicaciones, progreso y diagramas.

La idea es que cada pestana use los mismos bloques, para que el publico
reconozca el patron: primero "que esta pasando", luego el resultado, y
debajo una linea de "que significa esto en terminos de seguridad".
"""
import streamlit as st

from . import estado

# Marcas visuales de cada estado de un paso.
ICONO_ESTADO = {"hecho": "✅", "activo": "🔵", "bloqueado": "🔒"}
TEXTO_ESTADO = {"hecho": "Completado", "activo": "Te toca ahora", "bloqueado": "Bloqueado"}


def encabezado(icono: str, titulo: str, subtitulo: str) -> None:
    """Titulo de pestana con jerarquia consistente en toda la app."""
    st.subheader(f"{icono} {titulo}")
    st.caption(subtitulo)


def explicacion(titulo: str, que_pasa: str, por_que: str, expandido: bool = False) -> None:
    """Detalle tecnico plegable: visible para quien quiera, sin abrumar al resto."""
    with st.expander(f"🧠 {titulo}", expanded=expandido):
        st.markdown(f"**¿Qué está pasando técnicamente?**\n\n{que_pasa}")
        st.markdown(f"**¿Por qué importa para la seguridad?**\n\n{por_que}")


def interpretacion(texto: str) -> None:
    """Una linea que traduce un resultado tecnico a lenguaje de seguridad."""
    st.caption(f"🔎 **Qué significa:** {texto}")


def siguiente_paso(texto: str) -> None:
    """Pista de continuidad: que hacer despues de completar algo."""
    st.caption(f"➡️ **Siguiente:** {texto}")


def panel_bloqueado(paso: str, accion_texto: str | None = None) -> bool:
    """Muestra por que un paso no esta disponible todavia.

    Devuelve True si el paso esta bloqueado (la pestana debe detenerse ahi).
    Si se pasa `accion_texto`, ofrece un boton de atajo y devuelve tambien
    si el usuario lo pulso a traves de st.session_state.
    """
    falta = estado.falta_para(paso)
    if falta is None:
        return False
    st.warning(f"🔒 **Paso bloqueado.** {falta}")
    if accion_texto:
        st.caption(accion_texto)
    return True


def barra_progreso() -> None:
    """Barra + tarjetas numeradas con el estado de cada etapa del flujo."""
    estados = estado.estado_pasos()
    hechos, total = estado.progreso()
    actual = estado.paso_actual()

    st.progress(hechos / total, text=f"Progreso de la demo: {hechos} de {total} pasos completados")

    columnas = st.columns(total)
    for col, (i, (pid, etiqueta, icono)) in zip(columnas, enumerate(estado.PASOS, start=1)):
        est = estados[pid]
        with col.container(border=True):
            es_actual = pid == actual and est != "hecho"
            titulo = f"{ICONO_ESTADO[est]} **Paso {i}. {icono} {etiqueta}**"
            st.markdown(titulo)
            st.caption("👉 " + TEXTO_ESTADO[est] if es_actual else TEXTO_ESTADO[est])


def diagrama_flujo(paso: str) -> None:
    """Diagrama del flujo firmar -> verificar, resaltando la etapa actual.

    Se dibuja con Graphviz (DOT) que Streamlit renderiza sin dependencias
    extra. Los colores son fijos para que se lean igual en tema claro y oscuro.
    """
    # (nodo, paso que lo resalta)
    resaltar = {
        "claves": {"priv", "pub"},
        "firmar": {"doc", "hash", "firma"},
        "verificar": {"recibido", "hash2", "resultado"},
        "pki": {"pub", "ca"},
    }[paso]

    def nodo(nid: str, etiqueta: str, color: str, forma: str = "box") -> str:
        activo = nid in resaltar
        borde = '"#111111"' if activo else '"#B9C2CC"'
        grosor = "3" if activo else "1"
        relleno = f'"{color}"' if activo else '"#F1F3F5"'
        fuente = '"#111111"' if activo else '"#8A939B"'
        etiqueta = etiqueta.replace("\n", "\\n")  # DOT quiere \n literal, no un salto real
        return (f'{nid} [label="{etiqueta}", shape={forma}, style="filled,rounded", '
                f'fillcolor={relleno}, color={borde}, penwidth={grosor}, '
                f'fontcolor={fuente}, fontname="Helvetica", fontsize=11];')

    dot = f"""
    digraph flujo {{
      rankdir=LR;
      bgcolor="transparent";
      pad=0.2;
      nodesep=0.35;
      ranksep=0.5;
      edge [color="#9AA4AE", fontcolor="#9AA4AE", fontname="Helvetica", fontsize=9, arrowsize=0.7];

      subgraph cluster_firma {{
        label="Firmar (emisor)"; fontcolor="#9AA4AE"; fontname="Helvetica"; fontsize=10;
        color="#D5DBE1"; style=dashed;
        {nodo("doc", "Documento", "#DCEBFA")}
        {nodo("hash", "Huella\nSHA-256", "#DCEBFA")}
        {nodo("priv", "Clave\nprivada", "#FFE3C2", "ellipse")}
        {nodo("firma", "Firma\nRSA-PSS", "#DCEBFA")}
      }}

      subgraph cluster_verif {{
        label="Verificar (receptor)"; fontcolor="#9AA4AE"; fontname="Helvetica"; fontsize=10;
        color="#D5DBE1"; style=dashed;
        {nodo("recibido", "Documento\nrecibido", "#D8F2E0")}
        {nodo("hash2", "Huella\nrecalculada", "#D8F2E0")}
        {nodo("pub", "Clave\npública", "#FFE3C2", "ellipse")}
        {nodo("resultado", "¿Coincide?\nVálida / Inválida", "#D8F2E0", "diamond")}
      }}

      {nodo("ca", "CA: certificado\nX.509", "#EADCFB", "ellipse")}

      doc -> hash [label="SHA-256"];
      hash -> firma;
      priv -> firma [label="firma"];
      firma -> recibido [label="envío", style=dashed];
      recibido -> hash2 [label="SHA-256"];
      hash2 -> resultado;
      pub -> resultado [label="verifica"];
      ca -> pub [label="avala identidad", style=dotted];
    }}
    """
    st.graphviz_chart(dot, width="stretch")
    st.caption("En **naranja** las claves, en **morado** el aval de la CA. "
               "Resaltado el paso en el que estás.")
