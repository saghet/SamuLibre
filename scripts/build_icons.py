import os
import math
from PIL import Image, ImageDraw, ImageFilter

def create_master_icon(size=1024):
    """
    Renderiza el logo maestro de SamuLibre con 2x supersampling (2048x2048)
    para obtener bordes vectoriales con antialiasing perfecto y máxima legibilidad.
    """
    S = size * 2
    img = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    cx, cy = S / 2, S / 2

    # 1. Geometría del Escudo Samurai (Aprovecha 94% del espacio vertical)
    w_half = S * 0.43
    h_top = S * 0.08
    h_shoulder = S * 0.14
    h_mid = S * 0.48
    h_bottom = S * 0.94

    shield_pts = []
    # Borde superior curvado
    for i in range(25):
        t = i / 24.0
        x = cx + t * w_half
        y = h_top + (t**1.3) * (h_shoulder - h_top)
        shield_pts.append((x, y))

    # Lateral derecho
    for i in range(1, 16):
        t = i / 15.0
        x = cx + w_half * (1.0 + 0.02 * math.sin(t * math.pi))
        y = h_shoulder + t * (h_mid - h_shoulder)
        shield_pts.append((x, y))

    # Curva inferior derecha hacia la punta
    for i in range(1, 30):
        t = i / 29.0
        x = (1 - t)**2 * (cx + w_half) + 2 * (1 - t) * t * (cx + w_half * 0.38) + t**2 * cx
        y = (1 - t)**2 * h_mid + 2 * (1 - t) * t * (h_bottom * 0.92) + t**2 * h_bottom
        shield_pts.append((x, y))

    # Curva inferior izquierda desde la punta
    for i in range(1, 30):
        t = i / 29.0
        x = (1 - t)**2 * cx + 2 * (1 - t) * t * (cx - w_half * 0.38) + t**2 * (cx - w_half)
        y = (1 - t)**2 * h_bottom + 2 * (1 - t) * t * (h_bottom * 0.92) + t**2 * h_mid
        shield_pts.append((x, y))

    # Lateral izquierdo
    for i in range(1, 16):
        t = i / 15.0
        x = cx - w_half * (1.0 + 0.02 * math.sin((1 - t) * math.pi))
        y = h_mid - t * (h_mid - h_shoulder)
        shield_pts.append((x, y))

    # Superior izquierdo hacia el centro
    for i in range(1, 25):
        t = i / 24.0
        x = (cx - w_half) + t * w_half
        y = h_shoulder - (t**0.7) * (h_shoulder - h_top)
        shield_pts.append((x, y))

    # A. Resplandor exterior Neón
    glow = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    glow_draw = ImageDraw.Draw(glow)
    glow_draw.polygon(shield_pts, fill=(0, 245, 160, 140))
    glow = glow.filter(ImageFilter.GaussianBlur(radius=S * 0.028))
    img.paste(glow, (0, 0), glow)

    # B. Marco exterior grueso y vibrante (Esmeralda Neón #00FFA3 a Turquesa #00E5FF)
    draw.polygon(shield_pts, fill=(0, 245, 175, 255))

    # C. Interior del Escudo (Reducido 9% para dejar marco sólido de 18% relativo)
    inner_pts = []
    for x, y in shield_pts:
        ix = cx + (x - cx) * 0.86
        iy = cy + (y - cy) * 0.86 + S * 0.012
        inner_pts.append((ix, iy))

    # Fondo base del escudo (Obsidiana oscuro profundo #06151B)
    draw.polygon(inner_pts, fill=(6, 21, 27, 255))

    # Faceta izquierda iluminada (Esmeralda oscuro satinado #0B3831)
    left_inner = [(x, y) for x, y in inner_pts if x <= cx]
    left_inner.insert(0, (cx, h_top + S*0.04))
    left_inner.append((cx, h_bottom - S*0.06))
    draw.polygon(left_inner, fill=(11, 56, 49, 255))

    # Arista central vertical sutil
    draw.line([(cx, h_top + S*0.04), (cx, h_bottom - S*0.06)], fill=(52, 211, 153, 120), width=int(S * 0.012))

    # D. Emblema Central: Letra "S" en Blanco Puro de Alto Contraste
    s_w = S * 0.25
    s_h = S * 0.35
    s_cy = cy * 0.98
    stroke_s = int(S * 0.075)

    # Arco superior de la S
    draw.arc([cx - s_w*0.82, s_cy - s_h*0.88, cx + s_w*0.72, s_cy], start=140, end=395, fill=(255, 255, 255, 255), width=stroke_s)
    # Arco inferior de la S
    draw.arc([cx - s_w*0.72, s_cy - s_h*0.12, cx + s_w*0.82, s_cy + s_h*0.78], start=-40, end=220, fill=(255, 255, 255, 255), width=stroke_s)
    # Diagonal de conexión central
    draw.line([(cx + s_w*0.22, s_cy - s_h*0.06), (cx - s_w*0.22, s_cy + s_h*0.06)], fill=(255, 255, 255, 255), width=stroke_s)

    # E. Katana Samurai Diagonal (Hoja Brillante)
    kx1, ky1 = cx - S * 0.32, cy - S * 0.30
    kx2, ky2 = cx + S * 0.34, cy + S * 0.36
    blade_w = int(S * 0.036)

    # Hoja blanca con resplandor cian
    draw.line([(kx1, ky1), (kx2, ky2)], fill=(224, 242, 254, 255), width=blade_w)
    draw.line([(kx1, ky1), (kx2, ky2)], fill=(255, 255, 255, 255), width=int(blade_w * 0.6))

    # Guarda (Tsuba)
    tsuba_x, tsuba_y = cx - S * 0.22, cy - S * 0.20
    draw.ellipse([tsuba_x - S*0.045, tsuba_y - S*0.045, tsuba_x + S*0.045, tsuba_y + S*0.045], 
                 fill=(0, 245, 160, 255), outline=(255, 255, 255, 255), width=int(S*0.01))

    # Empuñadura (Tsuka)
    draw.line([(tsuba_x, tsuba_y), (tsuba_x - S*0.14, tsuba_y - S*0.14)], fill=(4, 120, 87, 255), width=int(blade_w * 1.3))
    # Rombos blancos de amarre de empuñadura
    draw.line([(tsuba_x - S*0.04, tsuba_y - S*0.04), (tsuba_x - S*0.06, tsuba_y - S*0.06)], fill=(255, 255, 255, 255), width=int(blade_w * 1.3))
    draw.line([(tsuba_x - S*0.09, tsuba_y - S*0.09), (tsuba_x - S*0.11, tsuba_y - S*0.11)], fill=(255, 255, 255, 255), width=int(blade_w * 1.3))
    # Pomo final (Kashira)
    draw.ellipse([tsuba_x - S*0.165, tsuba_y - S*0.165, tsuba_x - S*0.135, tsuba_y - S*0.135], fill=(0, 245, 160, 255))

    # Redimensionar con filtro Lanczos para un acabado impecable
    final = img.resize((size, size), Image.Resampling.LANCZOS)
    return final

def main():
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    assets_dir = os.path.join(root, "assets")
    os.makedirs(assets_dir, exist_ok=True)

    print("Generando logo maestro de 1024x1024...")
    master_1024 = create_master_icon(1024)

    # 1. Guardar icon.png y tray_icon.png
    master_512 = master_1024.resize((512, 512), Image.Resampling.LANCZOS)
    master_512.save(os.path.join(assets_dir, "icon.png"), "PNG")
    print("Guardado assets/icon.png (512x512)")

    # Para el tray icon, optimizamos a 64x64 con máximo detalle
    tray_64 = master_1024.resize((64, 64), Image.Resampling.LANCZOS)
    tray_64.save(os.path.join(assets_dir, "tray_icon.png"), "PNG")
    print("Guardado assets/tray_icon.png (64x64)")

    # 2. Guardar archivos .ico multirresolución de Windows (16, 24, 32, 48, 64, 128, 256)
    ico_sizes = [(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)]
    master_1024.save(
        os.path.join(assets_dir, "icon.ico"),
        format="ICO",
        sizes=ico_sizes
    )
    print("Guardado assets/icon.ico con 7 resoluciones nativas")

    master_1024.save(
        os.path.join(assets_dir, "tray_icon.ico"),
        format="ICO",
        sizes=ico_sizes
    )
    print("Guardado assets/tray_icon.ico con 7 resoluciones nativas")

if __name__ == "__main__":
    main()
