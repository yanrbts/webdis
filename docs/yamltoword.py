import yaml
from docx import Document

# def yaml_to_word_api_document(yaml_file, word_file):
#     # 读取 YAML 文件
#     with open(yaml_file, 'r', encoding='utf-8') as file:
#         yaml_data = yaml.safe_load(file)
    
#     # 创建 Word 文档
#     doc = Document()

#     # 添加 API 文档标题
#     doc.add_heading(f"{yaml_data['info']['title']} Documentation", 0)
#     doc.add_paragraph(f"Version: {yaml_data['info']['version']}")
#     doc.add_paragraph(f"Description: {yaml_data['info']['description']}")
#     doc.add_paragraph("\n")

#     # 初始化接口编号
#     api_counter = 1

#     # 处理每个路径
#     paths = yaml_data.get('paths', {})
#     for path, methods in paths.items():
#         for method, details in methods.items():
#             # 为每个 API 加上编号
#             doc.add_heading(f"{api_counter}. {path}", level=1)
#             doc.add_paragraph(f"Summary: {details.get('summary', 'No summary provided')}")
#             doc.add_paragraph(f"Method: {method.upper()}")
            
#             # 增加接口编号
#             api_counter += 1
            
#             # 请求体
#             if 'requestBody' in details:
#                 doc.add_heading('Request Body', level=2)
#                 content = details['requestBody']['content']
#                 for content_type, body_details in content.items():
#                     doc.add_paragraph(f"Content-Type: {content_type}")
#                     schema = body_details.get('schema', {})
#                     properties = schema.get('properties', {})
#                     required = schema.get('required', [])
                    
#                     # 添加请求体表格
#                     table = doc.add_table(rows=1, cols=4)
#                     hdr_cells = table.rows[0].cells
#                     hdr_cells[0].text = 'Field'
#                     hdr_cells[1].text = 'Type'
#                     hdr_cells[2].text = 'Description'
#                     hdr_cells[3].text = 'Required'

#                     for field, field_info in properties.items():
#                         row_cells = table.add_row().cells
#                         row_cells[0].text = field
#                         row_cells[1].text = field_info.get('type', 'N/A')
#                         row_cells[2].text = field_info.get('description', 'N/A')
#                         row_cells[3].text = 'Yes' if field in required else 'No'

#             # 响应体
#             if 'responses' in details:
#                 doc.add_heading('Responses', level=2)
#                 responses = details['responses']
#                 for status_code, response in responses.items():
#                     doc.add_paragraph(f"Status Code: {status_code} - {response.get('description', '')}")
#                     if 'content' in response:
#                         for content_type, response_details in response['content'].items():
#                             doc.add_paragraph(f"Content-Type: {content_type}")
#                             schema = response_details.get('schema', {})
#                             properties = schema.get('properties', {})
                            
#                             # 添加响应体表格
#                             table = doc.add_table(rows=1, cols=2)
#                             hdr_cells = table.rows[0].cells
#                             hdr_cells[0].text = 'Field'
#                             hdr_cells[1].text = 'Type'
                            
#                             for field, field_info in properties.items():
#                                 row_cells = table.add_row().cells
#                                 row_cells[0].text = field
#                                 row_cells[1].text = field_info.get('type', 'N/A')

#     # 保存 Word 文档
#     doc.save(word_file)
#     print(f'API Documentation saved to {word_file}')

import yaml
from docx import Document
from docx.oxml import OxmlElement
from docx.oxml.ns import qn

# 函数：为单元格设置背景颜色
def set_cell_background(cell, color):
    """Set background color of Word table cell."""
    cell_properties = cell._element.get_or_add_tcPr()
    shade = OxmlElement('w:shd')
    shade.set(qn('w:fill'), color)
    cell_properties.append(shade)

def yaml_to_word_api_document(yaml_file, word_file):
    # 读取 YAML 文件
    with open(yaml_file, 'r', encoding='utf-8') as file:
        yaml_data = yaml.safe_load(file)
    
    # 创建 Word 文档
    doc = Document()

    # 添加 API 文档标题
    doc.add_heading(f"{yaml_data['info']['title']} Documentation", 0)
    doc.add_paragraph(f"Version: {yaml_data['info']['version']}")
    doc.add_paragraph(f"Description: {yaml_data['info']['description']}")
    doc.add_paragraph("\n")

    # 初始化接口编号
    api_counter = 1

    # 处理每个路径
    paths = yaml_data.get('paths', {})
    for path, methods in paths.items():
        for method, details in methods.items():
            # 为每个 API 加上编号
            doc.add_heading(f"{api_counter}. {path}", level=1)
            doc.add_paragraph(f"Summary: {details.get('summary', 'No summary provided')}")
            doc.add_paragraph(f"Method: {method.upper()}")
            # 增加接口编号
            api_counter += 1
            
            # 请求体
            if 'requestBody' in details:
                doc.add_heading('Request Body', level=2)
                content = details['requestBody']['content']
                for content_type, body_details in content.items():
                    doc.add_paragraph(f"Content-Type: {content_type}")
                    schema = body_details.get('schema', {})
                    properties = schema.get('properties', {})
                    required = schema.get('required', [])
                    
                    # 添加请求体表格
                    table = doc.add_table(rows=1, cols=4)
                    hdr_cells = table.rows[0].cells
                    hdr_cells[0].text = 'Field'
                    hdr_cells[1].text = 'Type'
                    hdr_cells[2].text = 'Description'
                    hdr_cells[3].text = 'Required'

                    # 设置表头背景为暗灰色
                    for hdr_cell in hdr_cells:
                        set_cell_background(hdr_cell, 'D3D3D3')  # 使用暗灰色 (hex 代码为 D3D3D3)

                    for field, field_info in properties.items():
                        row_cells = table.add_row().cells
                        row_cells[0].text = field
                        row_cells[1].text = field_info.get('type', 'N/A')
                        row_cells[2].text = field_info.get('description', 'N/A')
                        row_cells[3].text = 'Yes' if field in required else 'No'

            # 响应体
            if 'responses' in details:
                doc.add_heading('Responses', level=2)
                responses = details['responses']
                for status_code, response in responses.items():
                    doc.add_paragraph(f"Status Code: {status_code} - {response.get('description', '')}")
                    if 'content' in response:
                        for content_type, response_details in response['content'].items():
                            doc.add_paragraph(f"Content-Type: {content_type}")
                            schema = response_details.get('schema', {})
                            properties = schema.get('properties', {})
                            
                            # 添加响应体表格
                            table = doc.add_table(rows=1, cols=4)
                            hdr_cells = table.rows[0].cells
                            hdr_cells[0].text = 'Field'
                            hdr_cells[1].text = 'Type'
                            hdr_cells[2].text = 'Description'
                            hdr_cells[3].text = 'Example'

                            # 设置表头背景为暗灰色
                            for hdr_cell in hdr_cells:
                                set_cell_background(hdr_cell, 'D3D3D3')  # 使用暗灰色 (hex 代码为 D3D3D3)
                            
                            def add_property_rows(properties, parent_key=''):
                                for field, field_info in properties.items():
                                    row_cells = table.add_row().cells
                                    field_name = f"{parent_key}.{field}" if parent_key else field
                                    row_cells[0].text = field_name
                                    field_type = field_info.get('type', 'N/A')
                                    field_description = field_info.get('description', 'N/A')
                                    field_example = field_info.get('example', 'N/A')

                                    row_cells[1].text = field_type
                                    row_cells[2].text = field_description
                                    row_cells[3].text = str(field_example)

                                    if field_type == 'array':
                                        item_type = field_info.get('items', {}).get('type', 'object')
                                        row_cells[1].text = f"Array of {item_type}"
                                        if item_type == 'object':
                                            nested_properties = field_info['items'].get('properties', {})
                                            add_property_rows(nested_properties, field_name)
                                    elif field_type == 'object':
                                        row_cells[1].text = 'Object'
                                        nested_properties = field_info.get('properties', {})
                                        add_property_rows(nested_properties, field_name)
                                    else:
                                        row_cells[1].text = field_type

                            add_property_rows(properties)

                            # for field, field_info in properties.items():
                            #     row_cells = table.add_row().cells
                            #     row_cells[0].text = field
                            #     row_cells[1].text = field_info.get('type', 'N/A')

    # 保存 Word 文档
    doc.save(word_file)
    print(f'API Documentation saved to {word_file}')

# 示例使用
yaml_file = '../api/api.yaml'  # 替换为你的 YAML 文件路径
word_file = 'api.docx'   # 要保存的 Word 文件名称
yaml_to_word_api_document(yaml_file, word_file)