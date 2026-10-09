---
layout: ../../../layouts/ArticleLayout.astro
lang: vi
title: "Lỗi ghi vào địa chỉ NULL trong Reshape của ONNX Runtime: Bài học từ báo cáo đã được MSRC đóng"
description: "Một initializer sai định dạng, hai bản ghi lỗi native và kết luận không phải lỗ hổng của MSRC: bài học từ ONNX-006 về kiểm tra dữ liệu, bằng chứng và tác động bảo mật."
published: "2026-10-10"
category: "Ghi chép nghiên cứu"
tags:
  - onnx-runtime
  - native-debugging
  - model-validation
  - research-lessons
draft: false
---

Trong quá trình nghiên cứu ONNX Runtime, chúng tôi ghi nhận một thao tác ghi vào địa chỉ 0 ở mã native khi nạp mô hình `Reshape` sai định dạng. Initializer chứa thông tin shape khai báo hai số nguyên 64 bit nhưng chỉ cung cấp hai byte dữ liệu thô. Bản phân tích nhị phân đã lưu cho thấy vùng đích có 0 phần tử nhưng độ dài sao chép vẫn lớn hơn 0 khi đến lời gọi `memmove`.

**MSRC đã đóng vụ việc với kết luận không đáp ứng định nghĩa lỗ hổng bảo mật của Microsoft và chưa đạt ngưỡng để được xử lý theo quy trình bảo mật.** Phản hồi cuối cùng cho biết phiên bản được đánh giá kiểm tra độ dài theo byte của `raw_data` trong initializer trước khi sao chép. MSRC đánh giá tác động là lỗi tiến trình có thể khôi phục khi ứng dụng nạp mô hình do kẻ tấn công cung cấp, không vượt qua ranh giới bảo mật. Vụ việc không đủ điều kiện nhận thưởng, sẽ không được cấp CVE và không được MSRC tiếp tục theo dõi.

Bài viết lưu lại cả quan sát kỹ thuật lẫn kết luận cuối cùng đó. Bài học hữu ích nằm ở cách gắn lỗi native với phạm vi tác động thực tế, trình bày trung thực những phần bằng chứng chưa đầy đủ và phân biệt phát hiện trên một tệp nhị phân trong quá khứ với đánh giá của nhà cung cấp.

*ONNX-006 là mã báo cáo nội bộ của chúng tôi, không phải mã vụ việc do MSRC cấp. Bản báo cáo lưu trữ đề ngày 13 tháng 9 năm 2026. Bài viết sử dụng hồ sơ sẵn có; chúng tôi không chạy mô hình hay chương trình tái hiện nào để chuẩn bị công bố.*

## Khai báo và dữ liệu của mô hình không khớp nhau

`Reshape` nhận một tensor dữ liệu và một tensor shape kiểu `INT64` mô tả các chiều đầu ra mong muốn. Đồ thị có thể cung cấp shape qua một initializer được lưu trong mô hình. [Đặc tả Reshape](https://onnx.ai/onnx/operators/onnx__Reshape.html) định nghĩa các đầu vào của toán tử; [đặc tả ONNX IR](https://onnx.ai/onnx/repo-docs/IR.html) giải thích cách initializer cung cấp giá trị cho đồ thị.

Mỗi initializer có kiểu dữ liệu, kích thước và dữ liệu đã tuần tự hóa riêng. Các kích thước đó mô tả chính initializer. Trong trường hợp này, `dims=[2]` nghĩa là initializer một chiều chứa **hai giá trị shape**; đây không phải shape đầu ra mà phép `Reshape` được yêu cầu tạo ra.

| Thuộc tính | Initializer sai định dạng được ghi nhận |
| --- | --- |
| Kiểu phần tử | `INT64`, tám byte cho mỗi phần tử khi mã hóa dạng thô |
| Kích thước initializer | `[2]` |
| Độ dài dữ liệu thô cần có | `2 × 8 = 16` byte |
| Độ dài dữ liệu thô được cung cấp | `2` byte |

Mã hóa dạng thô dùng các phần tử có độ rộng cố định và thứ tự byte little-endian. Cách mã hóa này khác với trường protobuf `int64_data` dành riêng cho kiểu dữ liệu đó. Vì vậy, hai byte thô không thể biểu diễn hai phần tử `INT64` đã khai báo. [Lược đồ TensorProto, ONNX v1.17.0](https://github.com/onnx/onnx/blob/v1.17.0/onnx/onnx.proto).

Đây là sự không nhất quán cần được kiểm tra trước khi có thể thực hiện suy luận có ý nghĩa. Trong thử nghiệm được lưu lại, lỗi xuất hiện khi tạo session. Bằng chứng không mô tả lỗi do một yêu cầu suy luận thông thường gây ra trên mô hình tin cậy đã được nạp sẵn.

## Phạm vi chính xác của đối tượng được kiểm tra

Báo cáo lưu trữ xác định đối tượng là `onnxruntime.dll` đi kèm Windows, được lấy từ **Windows Insider Dev build 10.0.29648.1000**. Cả hai bản ghi native đều ghi nhận chuỗi phiên bản runtime là **1.17.1** và cùng một giá trị băm DLL.

| Hạng mục | Phạm vi bằng chứng |
| --- | --- |
| Thành phần | Một tệp `onnxruntime.dll` x64 được định danh bằng giá trị băm |
| Build nguồn | 10.0.29648.1000, theo báo cáo lưu trữ |
| Nhãn phiên bản runtime | `1.17.1`, do chương trình thu thập bằng chứng ghi nhận |
| Mô hình | `reshape-short-notranspose.onnx`, 108 byte |
| Chương trình thử nghiệm | Windows x64, Python với `ctypes`, ONNX Runtime C API |
| Thời điểm hai bản ghi native | Ngày 12 tháng 9 năm 2026, lúc 15:27:38Z và 15:28:10Z |
| Thiết lập session | `CreateSession` từ tệp; script thu thập được lưu lại đã tắt tối ưu hóa đồ thị |

Build Windows nguồn của DLL không phải phiên bản Windows trên máy chạy chương trình thử nghiệm. Các bản ghi native được lưu lại không xác định build hệ điều hành hay phiên bản Python chính xác của máy đó. Chúng tôi không lấy thông tin môi trường từ những thử nghiệm khác để lấp các khoảng trống này.

```text
DLL SHA-256
d6e14879a5d697145c722a5e72bcfbffb4c187c5dcf0bf1d597cc060ba04bc72

Model SHA-256
8f1e2ef341ac96c49137aeae46b9359639f38c0670d9442f9993686b213b7484
```

Chuỗi `1.17.1` là thông tin nhận dạng do tệp nhị phân này trả về. Nó không xác lập một dải phiên bản bị ảnh hưởng cho các gói ONNX Runtime upstream, các bản phát hành Windows hay những DLL khác có cùng nhãn phiên bản.

## Những gì bản ghi native thể hiện

Cả hai bản ghi được lưu lại đều chứa các trường sau:

```text
code=0xC0000005
param[0]=0x0000000000000001
param[1]=0x0000000000000000
fault RVA (onnxruntime+0x75DE7B)
stack[RSP+0x0] = onnxruntime+0x6DDCBF
```

Với ngoại lệ vi phạm truy cập bộ nhớ, Windows quy định tham số ngoại lệ thứ nhất là loại truy cập và tham số thứ hai là địa chỉ không thể truy cập. Ở đây, `1` nghĩa là ghi và địa chỉ là 0. Điều này hỗ trợ mô tả **lỗi ghi vào địa chỉ NULL ở mã native**. [Tài liệu EXCEPTION_RECORD](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-exception_record).

Hai bản ghi khớp nhau về giá trị băm DLL và mô hình, RVA của lỗi và giá trị ở đỉnh stack. Như vậy, chúng tôi có hai quan sát đã lưu phù hợp với nhau. Một ghi chú nghiên cứu cũ nêu số lần lặp lại nhiều hơn, nhưng bộ bằng chứng công khai chỉ trực tiếp hỗ trợ hai lần này. [Bản ghi thứ nhất](/evidence/onnx-reshape-null-write/native-run-1.txt), [bản ghi thứ hai](/evidence/onnx-reshape-null-write/native-run-2.txt).

Đầu ra của chương trình thử nghiệm cung cấp thêm một chi tiết khiến chúng tôi điều chỉnh cách mô tả kết quả:

```text
OSError: exception: access violation writing 0x0000000000000000
```

`ctypes` chuyển ngoại lệ native thành một `OSError`, và chương trình thử nghiệm không xử lý ngoại lệ đó. Vì vậy, hồ sơ đã lưu hỗ trợ kết luận rằng chương trình thử nghiệm nạp mô hình này thất bại. Nó không chứng minh mọi ứng dụng tích hợp thư viện đều sẽ kết thúc, tiếp tục mất khả dụng hoặc khôi phục theo cùng một cách. [Đầu ra chương trình thử nghiệm lần 1](/evidence/onnx-reshape-null-write/harness-output-1.txt), [đầu ra lần 2](/evidence/onnx-reshape-null-write/harness-output-2.txt).

Chương trình ghi log cũng quét các giá trị trên stack để tìm giá trị nằm trong dải địa chỉ của DLL. **Kết quả quét đó không phải call stack được dựng lại bằng cơ chế unwind.** Chúng tôi dùng giá trị ở đỉnh stack để đối chiếu với vị trí gọi hàm đã lưu bên dưới; chúng tôi không biến mọi giá trị ứng viên ở sâu hơn thành một chuỗi hàm gọi theo thứ tự.

## Cấp phát và sao chép dùng hai độ dài khác nhau

Báo cáo trước đây có bản xuất đầy đủ gồm 179 lệnh của hàm được xác định là `onnx::ParseData<int64>`, bắt đầu tại VA `0x1806DDB64`. Nhánh xử lý dữ liệu thô chứa chuỗi lệnh sau:

```asm
1806ddca2  mov rdx, rdi
1806ddca5  shr rdx, 3
1806ddca9  mov rcx, rsi
1806ddcac  call std::vector<double>::resize(unsigned __int64)
1806ddcb1  mov r8, rdi
1806ddcb4  mov rdx, rbx
1806ddcb7  mov rcx, [rsi]
1806ddcba  call memmove
1806ddcbf  jmp short loc_1806DDC89
```

Bản phân tích đã lưu xác định `rdi` là độ dài dữ liệu thô theo byte. Phép dịch bit chia độ dài đó cho tám, bỏ phần dư, rồi dùng kết quả để thay đổi kích thước vùng đích. Sau đó, hàm sao chép lại nhận **độ dài byte ban đầu**. Với mẫu được ghi nhận:

```text
raw byte length               2
destination element count    2 >> 3 = 0
copy byte count              2

recorded initialized destination: NULL
resulting operation: memmove(NULL, source, 2)
```

Bản xuất đầy đủ còn cho thấy các trường của vector đích được đặt về 0 trước khi đi vào nhánh này. Cách giải thích đích NULL áp dụng cho vector được khởi tạo đó và trường hợp hai byte đã ghi nhận. Đây không phải khẳng định rằng con trỏ dữ liệu của mọi vector C++ rỗng đều là NULL.

Tên symbol khôi phục được của hàm resize là `std::vector<double>`. Chúng tôi giữ nguyên tên như trong bản xuất; nó không phải bằng chứng rằng mô hình chứa các giá trị shape dạng số thực. Các quan sát có ý nghĩa ở đây là phép tính kích thước theo đơn vị tám byte, trạng thái khởi tạo của vùng đích và số byte không đổi được truyền vào hàm sao chép. [Bản disassembly đầy đủ đã lưu](/evidence/onnx-reshape-null-write/parsedata-int64-complete.txt).

Với địa chỉ cơ sở của image là `0x180000000`, lệnh ngay sau lời gọi `memmove` có RVA `0x6DDCBF`. Giá trị đó khớp với giá trị ở đỉnh stack trong cả hai bản ghi native. Bản phân tích đã lưu đặt vị trí lỗi tại RVA `0x75DE7B` bên trong `memmove`. Khi đối chiếu với nhau, các bằng chứng này giải thích được lỗi đã ghi nhận mà không cần suy đoán một stack trace đầy đủ.

Hành vi mong muốn của bộ nạp là từ chối initializer không nhất quán trước khi thực hiện thao tác sao chép không hợp lệ. Việc giải thích luồng xử lý trong quá khứ này không chứng minh khả năng ghi tùy ý, chiếm quyền điều khiển luồng thực thi hay thực thi mã; bằng chứng đã nộp không chứng minh tác động nào trong số đó.

## Các phép đối chứng chứng minh được gì, và chưa chứng minh được gì

Hồ sơ nghiên cứu và báo cáo lưu trữ mô tả hai phép đối chứng:

| Đối chứng | Kết quả được ghi trong hồ sơ | Giới hạn |
| --- | --- | --- |
| Shape được mã hóa đúng bằng `int64_data` | Tạo session thành công | Mô hình này còn có `Transpose`; vì vậy, đây không phải phép so sánh chỉ thay đổi một yếu tố so với mô hình gây lỗi. |
| `Identity` sử dụng initializer `INT64` bị cắt ngắn | Từ chối bằng lỗi kích thước bộ đệm không khớp, không gây crash | Phép thử đi qua một đường sử dụng initializer khác, không bao quát mọi đường xử lý. |

Các kết quả này là thông tin được ghi lại trong hồ sơ nghiên cứu. Bộ bằng chứng công khai chứa hai bản ghi lỗi native và đầu ra tương ứng của chương trình thử nghiệm, không có bản ghi đầu ra thô riêng của các phép đối chứng. Người đọc nên cân nhắc mức độ chứng minh khác nhau của hai loại tài liệu này.

Thiết lập thu thập bằng chứng đã tắt tối ưu hóa đồ thị nhưng vẫn ghi nhận lỗi. Điều đó hỗ trợ kết luận hẹp hơn rằng thử nghiệm này không phụ thuộc vào việc bật các tối ưu hóa ấy. Nó không có nghĩa quá trình tạo session đã bỏ qua toàn bộ bước phân tích cú pháp, phân giải đồ thị hay xử lý shape.

## Kết luận cuối cùng của MSRC

Trong phản hồi cuối cùng được cung cấp cho bài viết, MSRC nêu rõ (**bản dịch tiếng Việt**):

> Sau khi xem xét kỹ lưỡng, vụ việc này không đáp ứng định nghĩa lỗ hổng bảo mật của Microsoft và chưa đạt ngưỡng để được xử lý theo quy trình bảo mật.

Phản hồi cũng cho biết (**bản dịch tiếng Việt**):

> Việc xử lý mô hình ONNX Reshape sai định dạng được báo cáo đã được giải quyết trong phiên bản được đánh giá thông qua kiểm tra độ dài theo byte của raw_data trong initializer trước khi sao chép.

MSRC đánh giá tác động còn lại là lỗi tiến trình có thể khôi phục khi ứng dụng nạp mô hình do kẻ tấn công cung cấp, không vượt qua ranh giới bảo mật. Phản hồi cho biết thông tin đã được chuyển tới nhóm kỹ thuật phụ trách để nắm tình hình và xem xét nội bộ. Phản hồi cũng xác nhận vụ việc không đủ điều kiện nhận thưởng, không được cấp CVE và không được MSRC tiếp tục theo dõi. [Toàn văn phản hồi cuối cùng, chép lại từ nội dung do người nghiên cứu cung cấp](/evidence/onnx-reshape-null-write/msrc-final-response.txt).

Phản hồi được cung cấp không nêu tên phiên bản đã đánh giá, commit sửa lỗi, bản phát hành đầu tiên có bản sửa, mã vụ việc MSRC hay ngày gửi ban đầu. Chúng tôi giữ nguyên trạng thái chưa biết của những thông tin này. Hồ sơ nhị phân tháng 9 không cho biết MSRC đã đánh giá phiên bản nào, và phản hồi cũng không xác lập một dải phiên bản đã sửa chung cho mọi trường hợp.

Đây là những loại bằng chứng khác nhau: các bản ghi phản ánh hành vi của một tệp nhị phân trong quá khứ; phản hồi cuối cùng ghi lại đánh giá và quyết định xử lý của nhà cung cấp. Chuyển báo cáo cho nhóm kỹ thuật không đồng nghĩa với chấp nhận nó là lỗ hổng bảo mật. Kết luận cũng không chỉ là từ chối tiền thưởng: MSRC đã nêu rõ vụ việc không đáp ứng định nghĩa lỗ hổng của họ.

## Những bài học rút ra

**Mô tả kết quả ở từng lớp.** Ngoại lệ native, việc chuyển nó thành ngoại lệ Python, sự thất bại của chương trình thử nghiệm và tính khả dụng của một ứng dụng triển khai thực tế là những quan sát riêng biệt. Hồ sơ của chúng tôi chứng minh ba điểm đầu cho chương trình thử nghiệm này. Nó không cung cấp thông tin về khả năng khôi phục hay tình trạng mất khả dụng kéo dài của một dịch vụ bị ảnh hưởng.

**Làm rõ đơn vị khi giải mã tensor.** Luồng xử lý đã ghi nhận dùng số phần tử để đặt kích thước vùng đích và số byte để sao chép. Điều kiện cần bảo đảm trước khi sao chép là shape đã khai báo, độ dài dữ liệu mã hóa theo byte và sức chứa vùng đích phải khớp nhau. Tuyên bố của MSRC về kiểm tra độ dài đề cập đến cùng vấn đề kiểm tra tính hợp lệ đó trong phiên bản họ đánh giá.

**Thử nghiệm nạp mô hình cần bối cảnh ứng dụng chính xác.** Đầu vào ở đây là toàn bộ mô hình sai định dạng được nạp qua C API. Chúng tôi không chứng minh được đường chuyển mô hình từ xa, một ứng dụng của nhà cung cấp thực sự nạp nó, khả năng thoát khỏi cơ chế cô lập hay chuyển đổi đặc quyền. Nêu rõ các giới hạn đó giúp báo cáo hữu ích hơn so với gán tác động giả định lên một dịch vụ từ kết quả của chương trình thử nghiệm cục bộ.

**Giữ lại thông tin nhận dạng và bằng chứng giới hạn kết luận.** Giá trị băm của tệp nhị phân giúp tránh biến nhãn phiên bản runtime thành một tuyên bố thiếu cơ sở về các phiên bản bị ảnh hưởng. Ngữ cảnh đầy đủ của hàm giúp giải thích đoạn lệnh ngắn được trích dẫn. Những giới hạn của phép đối chứng và `OSError` không được xử lý vẫn là một phần của câu chuyện, kể cả khi chúng thu hẹp cách diễn giải ban đầu.

**Một vụ việc đã đóng vẫn có thể giúp cải thiện thực hành kỹ thuật.** Với ứng dụng nhập mô hình, kiểm tra dữ liệu và giới hạn phạm vi ảnh hưởng của lỗi vẫn là những vấn đề hữu ích về độ tin cậy. Tài liệu của ONNX Runtime khuyến nghị kiểm tra mô hình từ nguồn không tin cậy và thử nghiệm trong môi trường an toàn trước khi đưa vào vận hành. Hướng dẫn chung đó không phải khẳng định rằng vụ việc này đã vượt qua một ranh giới bảo mật. [Hướng dẫn kiểm tra mô hình của ONNX Runtime](https://onnxruntime.ai/docs/#model-validation).

Bài học chúng tôi mang theo là bảo đảm bằng chứng hỗ trợ đúng tuyên bố được đưa ra. Ở đây, lỗi ghi vào địa chỉ NULL trong quá khứ có hồ sơ rõ ràng tồn tại song song với kết luận cuối cùng rằng vụ việc không phải lỗ hổng bảo mật. Cả hai đều cần có mặt trong hồ sơ chia sẻ với cộng đồng.

## Bằng chứng và nguồn gốc

[Gói bằng chứng](/evidence/onnx-reshape-null-write/evidence.zip) chứa hai bản ghi native, hai đầu ra của chương trình thử nghiệm, bản xuất đầy đủ của hàm đã lưu, phản hồi cuối cùng được cung cấp từ MSRC và ghi chú nguồn gốc bằng tiếng Anh cùng tiếng Việt. [Manifest](/evidence/onnx-reshape-null-write/manifest.json) ghi lại giá trị SHA-256 của các tệp gốc và tệp công khai. Tiền tố đường dẫn thư mục nghiên cứu cục bộ được thay bằng `<research-root>`; các thay đổi về định dạng được ghi trong phần hướng dẫn. Đây là tập hợp hồ sơ trong quá khứ, không phải kết quả chạy tái hiện mới.

Các tệp riêng lẻ được liên kết ở trên, kèm [hướng dẫn đọc bằng chứng bằng tiếng Anh](/evidence/onnx-reshape-null-write/README.en.txt) và [hướng dẫn bằng tiếng Việt](/evidence/onnx-reshape-null-write/README.vi.txt). Giá trị băm mô hình và DLL định danh các đầu vào gốc; gói bằng chứng dạng văn bản này không kèm mô hình hay DLL.
