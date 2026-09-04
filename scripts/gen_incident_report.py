#!/usr/bin/env python3
"""生成便携式AI算力主站故障情况说明 Word文档"""

from docx import Document
from docx.shared import Pt, Cm, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.oxml.ns import qn
import os

doc = Document()

# ── 页面设置 ──
section = doc.sections[0]
section.page_width = Cm(21)
section.page_height = Cm(29.7)
section.top_margin = Cm(2.54)
section.bottom_margin = Cm(2.54)
section.left_margin = Cm(3.17)
section.right_margin = Cm(3.17)

# ── 默认字体 ──
style = doc.styles['Normal']
style.font.name = '宋体'
style.font.size = Pt(12)
style.element.rPr.rFonts.set(qn('w:eastAsia'), '宋体')
style.paragraph_format.line_spacing = 1.5

def add_heading_cn(text, level=1):
    h = doc.add_heading(text, level=level)
    for run in h.runs:
        run.font.name = '黑体'
        run.element.rPr.rFonts.set(qn('w:eastAsia'), '黑体')
        run.font.color.rgb = RGBColor(0, 0, 0)
    return h

def add_para(text, bold=False, indent=False, font_name='宋体', font_size=Pt(12)):
    p = doc.add_paragraph()
    if indent:
        p.paragraph_format.first_line_indent = Cm(0.74)
    run = p.add_run(text)
    run.font.name = font_name
    run.font.size = font_size
    run.element.rPr.rFonts.set(qn('w:eastAsia'), font_name)
    run.bold = bold
    return p

def add_field(label, value):
    """添加一个 '标签：值' 格式的段落，标签加粗"""
    p = doc.add_paragraph()
    p.paragraph_format.first_line_indent = Cm(0.74)
    r1 = p.add_run(label)
    r1.font.name = '宋体'
    r1.font.size = Pt(12)
    r1.element.rPr.rFonts.set(qn('w:eastAsia'), '宋体')
    r1.bold = True
    r2 = p.add_run(value)
    r2.font.name = '宋体'
    r2.font.size = Pt(12)
    r2.element.rPr.rFonts.set(qn('w:eastAsia'), '宋体')
    return p

# ════════════════════════════════════════════════════════
# 标题
# ════════════════════════════════════════════════════════
title = doc.add_paragraph()
title.alignment = WD_ALIGN_PARAGRAPH.CENTER
run = title.add_run('关于便携式 AI 算力主站故障的情况说明')
run.font.name = '黑体'
run.font.size = Pt(18)
run.element.rPr.rFonts.set(qn('w:eastAsia'), '黑体')
run.bold = True

doc.add_paragraph()  # 空行

# ════════════════════════════════════════════════════════
# 一、基本信息
# ════════════════════════════════════════════════════════
add_heading_cn('一、基本信息', level=2)

add_field('设备名称：', '便携式 AI 算力主站')
add_field('设备配置：', 'x86（海光）架构，2×RTX 4090 + 1×Tesla T4，320GB RAM，8TB SSD，12路 PoE')
add_field('所属实验室：', '9424')
add_field('故障日期：', '2026 年 8 月 15 日')
add_field('报告人：', '（请填写姓名）')
add_field('报告日期：', '2026 年 8 月 15 日')

# ════════════════════════════════════════════════════════
# 二、故障现象
# ════════════════════════════════════════════════════════
add_heading_cn('二、故障现象', level=2)

add_para('设备在正常运行过程中突然发出一声"砰"响，随即整机断电，所有指示灯熄灭，设备完全无响应。断电后能闻到一股烧焦气味。尝试再次按下电源开关开机，设备无任何反应。', indent=True)

# ════════════════════════════════════════════════════════
# 三、故障发生时设备运行状态
# ════════════════════════════════════════════════════════
add_heading_cn('三、故障发生时设备运行状态', level=2)

add_para('故障发生时，设备处于带载运行状态，具体情况如下：', indent=True)

add_field('运行项目：', '服务器上同时运行两个项目（均为开机自启）：')
p = doc.add_paragraph()
p.paragraph_format.first_line_indent = Cm(1.48)
r = p.add_run('1）信息系统安全智能化测试平台（RedTeam-Platform）；')
r.font.name = '宋体'; r.font.size = Pt(12); r.element.rPr.rFonts.set(qn('w:eastAsia'), '宋体')

p = doc.add_paragraph()
p.paragraph_format.first_line_indent = Cm(1.48)
r = p.add_run('2）pentagi-v3。')
r.font.name = '宋体'; r.font.size = Pt(12); r.element.rPr.rFonts.set(qn('w:eastAsia'), '宋体')

add_field('云笔电连接情况：', '共 5 台云笔电（飞腾 E2000Q，ARM64）已开机并连接至服务器。')
add_field('网络接口使用情况：', '服务器主板上方一组的 6 个接口全部插满，其中 5 个连接云笔电（开机状态），1 个通过网线连接路由器。')
add_para('上述运行状态意味着故障发生时，服务器 CPU、GPU（3 张显卡）及网络端口均处于工作状态，整机功耗较高。', indent=True)

# ════════════════════════════════════════════════════════
# 四、故障后检查情况
# ════════════════════════════════════════════════════════
add_heading_cn('四、故障后检查情况', level=2)

add_para('故障发生后，我打开设备外壳进行目视检查，具体如下：', indent=True)

add_field('检查方式：', '仅打开外壳观察，未对内部部件进行拆卸（避免造成二次损坏）。')
add_field('检查结果：', '在目视可观察的范围内，未发现烧蚀、变色、鼓包、熔化等明显异常痕迹。')
add_field('拍照记录：', '已对设备内部拍照存证。')
add_para('需要说明的是，目视检查存在局限性：部分元器件（如贴片 MOSFET、BGA 封装芯片内部、电源模块内部电容等）即使已损坏，外观也可能无明显变化，因此目视无异常不能排除硬件损坏的可能。', indent=True)

# ════════════════════════════════════════════════════════
# 五、初步分析
# ════════════════════════════════════════════════════════
add_heading_cn('五、初步分析', level=2)

add_para('根据"砰响 + 断电 + 烧焦味"这一典型故障特征，初步判断为电气击穿或元器件爆裂，可能原因包括：', indent=True)

p = doc.add_paragraph()
p.paragraph_format.first_line_indent = Cm(1.48)
r = p.add_run('1）电源模块（PSU）内部电容爆裂：高功耗设备电源故障率较高，电容爆裂会产生砰响并伴随烧焦气味，且电源外壳内部损坏从外部难以观察。')
r.font.name = '宋体'; r.font.size = Pt(12); r.element.rPr.rFonts.set(qn('w:eastAsia'), '宋体')

p = doc.add_paragraph()
p.paragraph_format.first_line_indent = Cm(1.48)
r = p.add_run('2）主板或 GPU 供电相路上的功率器件（MOSFET）击穿：设备配置 3 张高功耗显卡（2×RTX 4090 + 1×Tesla T4），GPU 供电回路长期高负载运行，功率器件击穿风险较高。')
r.font.name = '宋体'; r.font.size = Pt(12); r.element.rPr.rFonts.set(qn('w:eastAsia'), '宋体')

p = doc.add_paragraph()
p.paragraph_format.first_line_indent = Cm(1.48)
r = p.add_run('3）GPU 供电接口问题：RTX 4090 采用 12VHPWR 供电接口，该接口在业界已有过接触不良导致过热熔毁的案例，值得重点关注。')
r.font.name = '宋体'; r.font.size = Pt(12); r.element.rPr.rFonts.set(qn('w:eastAsia'), '宋体')

add_para('鉴于目视检查未发现明显痕迹，确切故障点需使用专业检测设备（万用表、示波器等）进一步定位，或由厂商售后进行专业检测。', indent=True)

# ════════════════════════════════════════════════════════
# 六、处置情况与建议
# ════════════════════════════════════════════════════════
add_heading_cn('六、处置情况与建议', level=2)

add_field('已采取措施：', '故障后未再对设备通电，已打开外壳拍照存证。')
add_para('后续建议：', bold=True, indent=True)

p = doc.add_paragraph()
p.paragraph_format.first_line_indent = Cm(1.48)
r = p.add_run('1）设备暂勿再次通电，以免造成二次损坏或引发安全隐患；')
r.font.name = '宋体'; r.font.size = Pt(12); r.element.rPr.rFonts.set(qn('w:eastAsia'), '宋体')

p = doc.add_paragraph()
p.paragraph_format.first_line_indent = Cm(1.48)
r = p.add_run('2）联系设备供应商或厂商售后，安排专业检测与维修；')
r.font.name = '宋体'; r.font.size = Pt(12); r.element.rPr.rFonts.set(qn('w:eastAsia'), '宋体')

p = doc.add_paragraph()
p.paragraph_format.first_line_indent = Cm(1.48)
r = p.add_run('3）如在保修期内，保留设备现状以便保修处理。')
r.font.name = '宋体'; r.font.size = Pt(12); r.element.rPr.rFonts.set(qn('w:eastAsia'), '宋体')

# ════════════════════════════════════════════════════════
# 七、附件
# ════════════════════════════════════════════════════════
add_heading_cn('七、附件', level=2)

add_para('设备内部拍照（见附图）', indent=True)

# ── 落款 ──
doc.add_paragraph()
doc.add_paragraph()

p = doc.add_paragraph()
p.alignment = WD_ALIGN_PARAGRAPH.RIGHT
r = p.add_run('报告人：（签名）')
r.font.name = '宋体'; r.font.size = Pt(12); r.element.rPr.rFonts.set(qn('w:eastAsia'), '宋体')

p = doc.add_paragraph()
p.alignment = WD_ALIGN_PARAGRAPH.RIGHT
r = p.add_run('日期：2026 年 8 月 15 日')
r.font.name = '宋体'; r.font.size = Pt(12); r.element.rPr.rFonts.set(qn('w:eastAsia'), '宋体')

# ── 保存 ──
output_dir = os.path.dirname(os.path.abspath(__file__))
# 实际保存到项目根目录的 docs 下
project_root = os.path.dirname(output_dir)
output_path = os.path.join(project_root, 'docs', '便携式AI算力主站故障情况说明.docx')
doc.save(output_path)
print(f'文档已生成：{output_path}')
