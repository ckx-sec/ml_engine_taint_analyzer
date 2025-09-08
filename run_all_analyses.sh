#!/bin/bash

# 设置 -e 选项，使得脚本在遇到任何错误时立即退出
set -e

# --- 全局配置 ---
# 定义统一的 Ghidra 项目名称
GHIDRA_PROJECT_DIR="ghidra_projects"
SINGLE_GHIDRA_PROJECT_NAME="all_binaries_analysis"
SINGLE_GHIDRA_PROJECT_PATH="$GHIDRA_PROJECT_DIR/$SINGLE_GHIDRA_PROJECT_NAME.gpr"
SINGLE_GHIDRA_PROJECT_REP_PATH="$GHIDRA_PROJECT_DIR/$SINGLE_GHIDRA_PROJECT_NAME.rep"

# 定义存放二进制文件的目录
BIN_DIR="assets/merged_bin"
# 定义分析脚本的列表
ANALYZERS=("mnn_analyzer.py" "tflite_analyzer.py" "onnxruntime_analyzer.py" "ncnn_analyzer.py")
# 定义用于执行分析的核心脚本
HEADLESS_RUNNER="run_headless_test.sh"

# --- 前置检查 ---
# 检查核心执行脚本是否存在且可执行
if [ ! -x "$HEADLESS_RUNNER" ]; then
    echo "错误: $HEADLESS_RUNNER 未找到或没有执行权限。"
    exit 1
fi

# 检查所有分析器脚本是否存在
for analyzer in "${ANALYZERS[@]}"; do
    if [ ! -f "$analyzer" ]; then
        echo "错误: 分析器脚本 $analyzer 未找到。"
        exit 1
    fi
done

# 检查二进制文件目录是否存在
if [ ! -d "$BIN_DIR" ]; then
    echo "错误: 目录 $BIN_DIR 未找到。"
    exit 1
fi

echo "--- 清理旧的统一 Ghidra 项目 (如果存在) ---"
if [ -f "$SINGLE_GHIDRA_PROJECT_PATH" ]; then
    echo "正在删除旧的 Ghidra 项目文件: $SINGLE_GHIDRA_PROJECT_PATH"
    rm -f "$SINGLE_GHIDRA_PROJECT_PATH"
fi
if [ -d "$SINGLE_GHIDRA_PROJECT_REP_PATH" ]; then
    echo "正在删除旧的 Ghidra 项目数据目录: $SINGLE_GHIDRA_PROJECT_REP_PATH"
    rm -rf "$SINGLE_GHIDRA_PROJECT_REP_PATH"
fi
echo "旧项目清理完毕。"
echo ""


echo "--- 开始批量分析 ---"

# 遍历指定目录下的所有文件
for executable_path in "$BIN_DIR"/*; do
    # 确保我们处理的是一个文件并且它具有执行权限
    if [ -f "$executable_path" ] && [ -x "$executable_path" ]; then
        
        filename=$(basename -- "$executable_path")

        # --- 新增：根据前缀排除特定的可执行文件 ---
        case "$filename" in
            mnist*|yolov5*|ultraface*|pfld*)
                echo "跳过: $filename (根据前缀排除规则)"
                continue
                ;;
        esac
        
        analyzer_script=""
        framework_name=""

        # --- 新的文件名解析逻辑 ---
        # 移除可能的 .bin 后缀 (虽然可执行文件通常没有)
        filename_no_ext="${filename%.*}"
        # 使用下划线分割文件名
        IFS='_' read -r -a parts <<< "$filename_no_ext"
        num_parts=${#parts[@]}

        # 检查文件名是否至少有三个部分 (例如: model_framework_category)
        if [ $num_parts -ge 3 ]; then
            # 倒数第三个字段是框架
            framework_field="${parts[num_parts-3]}"
            # 倒数第二个字段是分类
            category="${parts[num_parts-2]}"
            # 倒数第一个字段是子项
            item="${parts[num_parts-1]}"

            case "$framework_field" in
                mnn)
                    analyzer_script="mnn_analyzer.py"; framework_name="MNN" ;;
                tflite)
                    analyzer_script="tflite_analyzer.py"; framework_name="TFLite" ;;
                onnxruntime)
                    analyzer_script="onnxruntime_analyzer.py"; framework_name="ONNX Runtime" ;;
                ncnn)
                    analyzer_script="ncnn_analyzer.py"; framework_name="NCNN" ;;
                tnn)
                    framework_name="TNN"; analyzer_script="" ;;
                *)
                    framework_name=""; analyzer_script="" ;;
            esac

            # 如果找到了匹配的分析脚本，则执行分析
            if [ -n "$analyzer_script" ]; then
                # --- 构造新的输出路径 ---
                output_dir="results/$category/$item"
                # 确保输出目录存在
                mkdir -p "$output_dir"
                # 完整的输出json文件路径
                output_json_path="$output_dir/${filename}_hook_config.json"
                
                echo ""
                echo "======================================================================"
                echo "正在对 [$filename] 执行 [$framework_name] 分析..."
                echo "  - Ghidra Project: $SINGLE_GHIDRA_PROJECT_NAME"
                echo "  - 输出路径: $output_json_path"
                echo "======================================================================"
                
                # 执行分析命令, 传入统一的项目名称和期望的输出路径
                ./"$HEADLESS_RUNNER" "$analyzer_script" "$executable_path" "$SINGLE_GHIDRA_PROJECT_NAME" "$output_json_path"
                
                echo "--- [$filename] 分析完成 ---"
            else
                if [ "$framework_name" == "TNN" ]; then
                    echo "跳过: $filename (TNN 分析器暂不支持)"
                else
                    echo "跳过: $filename (在倒数第三字段未找到对应的分析器: '$framework_field')"
                fi
            fi
        else
            echo "跳过: $filename (文件名格式不符合 'name_framework_category_item' 规范)"
        fi
    fi
done

echo ""
echo "======================================================================"
echo "所有分析任务已全部执行完毕。"
echo "======================================================================"
