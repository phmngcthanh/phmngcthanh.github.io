Initializer Reshape trong ONNX Runtime: bằng chứng lịch sử
Công bố ngày 2026-10-10 | Mã hồ sơ: VR-2026-006 / ONNX-006

Kết luận cuối cùng của MSRC là trường hợp này không đáp ứng định nghĩa lỗ hổng bảo mật của Microsoft và nằm dưới ngưỡng xử lý bản vá. MSRC đánh giá tác động là lỗi tiến trình có thể khôi phục, không vượt qua ranh giới bảo mật; đồng thời cho biết phiên bản được đánh giá kiểm tra độ dài raw_data trước khi sao chép. Hồ sơ đã đóng: không có bounty, không cấp CVE và MSRC không tiếp tục theo dõi. Kết luận này thay thế phân loại bảo mật và các đề nghị trong báo cáo ban đầu. Phản hồi được chép riêng trong msrc-final-response.txt; các nhận định kỹ thuật đó được dẫn theo MSRC, không phải kết quả kiểm chứng lại trong lần công bố này.

Các tệp

- native-run-1.txt và native-run-2.txt: hai bản ghi ngoại lệ native đã lưu ngày 2026-09-12, có cùng hash DLL và model. Cả hai ghi nhận ngoại lệ 0xC0000005, thao tác ghi vào địa chỉ 0, RVA gây lỗi onnxruntime+0x75DE7B và một giá trị trên đỉnh stack là onnxruntime+0x6DDCBF.
- harness-output-1.txt và harness-output-2.txt: traceback Python tương ứng đã lưu. Nội dung hai tệp giống nhau. ctypes biểu diễn ngoại lệ native dưới dạng OSError thoát ra ngoài chương trình thử nghiệm này.
- parsedata-int64-complete.txt: bản disassembly đầy đủ đã lưu của ParseData<int64>, ngày 2026-09-13, gồm 179 lệnh có địa chỉ. Phần chú thích đầu tệp ban đầu được giữ nguyên. Tệp mô tả DLL lịch sử được xác định bằng hash, không đại diện cho mọi bản ONNX Runtime hoặc phiên bản MSRC đã đánh giá.
- manifest.json: tên và SHA-256 của tệp gốc trong kho lưu trữ, tên và SHA-256 của bản công khai, phép biến đổi, thông tin định danh DLL/model và giới hạn của bằng chứng.
- msrc-final-response.txt: phản hồi cuối cùng do tác giả cung cấp cho lần công bố này; không phải advisory công khai của Microsoft được xác thực riêng.

Nguồn gốc và giới hạn

Tiền tố đường dẫn thư mục nghiên cứu cục bộ trong năm tệp lịch sử đã được thay bằng <research-root>; các giá trị ngoại lệ, địa chỉ và lệnh được giữ nguyên. Hash của tệp nguồn không trùng với hash của bản công khai đã ẩn đường dẫn. Hãy dùng published_sha256 trong manifest.json để kiểm tra tệp tải về.

Phần đầu bản disassembly vẫn nhắc đến tên tệp trong kho gốc. Manifest đối chiếu các tên đó với tên tệp công khai. Bản trích đoạn có chú thích được nhắc riêng trong phần đầu không nằm trong gói; gói này cung cấp toàn bộ hàm.

Bộ ghi native quét các giá trị thô trên stack để tìm địa chỉ nằm trong module. Đây không phải call stack được unwind đầy đủ. Có thể đối chiếu giá trị trên đỉnh stack với vị trí gọi hàm; không được diễn giải các mục sâu hơn thành chuỗi hàm gọi theo thứ tự.

Ghi chép nghiên cứu gốc báo cáo các đối chứng mã hóa hợp lệ, từ chối dữ liệu lỗi một cách có kiểm soát và kết quả tổng cộng 5/5. Gói này chứa hai bản ghi native, không phải năm, và không có log thô riêng cho các lần chạy đối chứng. Vì vậy kết quả đối chứng chỉ được dẫn theo ghi chép nghiên cứu. Đối chứng int64_data hợp lệ trong chương trình thử nghiệm gốc còn có nút Transpose, nên không phải phép so sánh chỉ thay đổi một biến trong graph.

Theo hồ sơ gửi đi, DLL được lấy từ Windows Insider Dev 10.0.29648.1000. Môi trường lấy DLL và môi trường chạy thử là hai thông tin khác nhau. Các bản ghi ONNX-006 này không ghi rõ build Windows hoặc phiên bản Python của máy chạy. Chuỗi phiên bản runtime 1.17.1 không xác định dải phiên bản upstream bị ảnh hưởng.

Đây là kho bằng chứng phục vụ bài học rút ra từ một hồ sơ đã đóng. Gói không phân phối model, DLL hoặc chương trình thực thi để tái hiện lỗi. Không chạy thử lại khi chuẩn bị công bố. Các hiện vật không chứng minh khả năng ghi tùy ý, thực thi mã, leo thang đặc quyền hoặc vượt qua ranh giới bảo mật. Những nhãn cũ như "defect" trong phần đầu bản disassembly phản ánh cách diễn giải tại thời điểm nghiên cứu; chúng không thay thế kết luận cuối cùng của MSRC.
