import cv2
import numpy as np
from ultralytics import YOLO
import datetime
from collections import defaultdict
import threading
import queue
import time

class ImprovedVehicleAndPeopleDetector:
    def __init__(self, video_path, output_path='improved_output.mp4'):
        print("🚀 Initializing Improved Vehicle & People Detector...")
        
        # Use YOLOv8s for better accuracy (upgraded from yolov8n)
        self.model = YOLO("yolov8s.pt")  # More accurate than yolov8n.pt
        
        # Enhanced configuration for better detection of both vehicles and people
        self.conf_threshold = 0.25  # Lowered for better detection (was 0.35)
        self.iou_threshold = 0.45    # Improved accuracy (was 0.5)
        self.track_history = defaultdict(lambda: [])
        
        # Performance optimizations
        self.frame_skip = 2  # Process every 2nd frame for 2x speed boost
        self.resize_factor = 0.8  # Resize frames to 80% for faster processing
        self.max_track_length = 20  # Reduced from 30 for better performance
        
        # Initialize video
        self.video_cap = cv2.VideoCapture(video_path)
        if not self.video_cap.isOpened():
            raise Exception(f"❌ Cannot open video: {video_path}")
        
        # Get original video properties
        self.original_fps = int(self.video_cap.get(cv2.CAP_PROP_FPS))
        self.original_width = int(self.video_cap.get(cv2.CAP_PROP_FRAME_WIDTH))
        self.original_height = int(self.video_cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
        
        # Calculate processing dimensions
        self.process_width = int(self.original_width * self.resize_factor)
        self.process_height = int(self.original_height * self.resize_factor)
        
        print(f"✅ Original: {self.original_width}x{self.original_height}")
        print(f"✅ Processing: {self.process_width}x{self.process_height}")
        
        # Initialize output video writer
        fourcc = cv2.VideoWriter_fourcc(*'mp4v')
        self.out = cv2.VideoWriter(output_path, fourcc, self.original_fps, 
                                  (self.original_width, self.original_height))
        
        # Vehicle and people counting
        self.total_count = 0
        self.people_count = 0
        self.vehicle_count = 0
        self.counted_objects = set()
        self.counting_line_y = self.process_height // 2
        self.id_mapping = {}
        self.next_clean_id = 1
        
        # Performance tracking
        self.fps_history = []
        self.detection_confidence_sum = 0
        self.detection_count = 0
        
        # Enhanced classes - NOW INCLUDES PEOPLE! 👥
        self.target_classes = {
            0: 'person',        # 👥 PEOPLE DETECTION ADDED!
            1: 'bicycle', 
            2: 'car', 
            3: 'motorcycle', 
            5: 'bus', 
            7: 'truck'
        }
        
        # Color coding for different object types
        self.colors = {
            'person': (255, 0, 255),      # Magenta for people
            'bicycle': (0, 255, 255),     # Cyan for bicycles
            'car': (0, 255, 0),           # Green for cars
            'motorcycle': (255, 255, 0),  # Yellow for motorcycles
            'bus': (255, 0, 0),           # Blue for buses
            'truck': (0, 0, 255)          # Red for trucks
        }
        
    def preprocess_frame(self, frame):
        """Optimize frame for better detection of people and vehicles"""
        # Resize for faster processing
        processed_frame = cv2.resize(frame, (self.process_width, self.process_height))
        
        # Enhanced contrast for better person detection
        lab = cv2.cvtColor(processed_frame, cv2.COLOR_BGR2LAB)
        l, a, b = cv2.split(lab)
        clahe = cv2.createCLAHE(clipLimit=2.5, tileGridSize=(8,8))  # Slightly increased for better people detection
        l = clahe.apply(l)
        enhanced_frame = cv2.merge([l, a, b])
        enhanced_frame = cv2.cvtColor(enhanced_frame, cv2.COLOR_LAB2BGR)
        
        return enhanced_frame
    
    def detect_and_track(self, frame):
        """Enhanced detection for both vehicles and people"""
        start_time = time.time()
        
        # Preprocess frame for better detection
        processed_frame = self.preprocess_frame(frame)
        
        # Run YOLO with optimized parameters for people and vehicles
        results = self.model.track(
            processed_frame, 
            conf=self.conf_threshold,
            iou=self.iou_threshold,
            persist=True,
            verbose=False,
            device='0' if cv2.cuda.getCudaEnabledDeviceCount() > 0 else 'cpu',
            classes=list(self.target_classes.keys())  # Only detect our target classes
        )
        
        detections = []
        
        # Process results
        if results[0].boxes is not None and results[0].boxes.id is not None:
            boxes = results[0].boxes.xyxy.cpu().numpy()
            track_ids = results[0].boxes.id.int().cpu().tolist()
            confidences = results[0].boxes.conf.cpu().numpy()
            class_ids = results[0].boxes.cls.int().cpu().tolist()
            
            for box, track_id, conf, class_id in zip(boxes, track_ids, confidences, class_ids):
                if class_id in self.target_classes and conf > self.conf_threshold:
                    # Scale coordinates back to original size
                    x1 = int(box[0] / self.resize_factor)
                    y1 = int(box[1] / self.resize_factor)
                    x2 = int(box[2] / self.resize_factor)
                    y2 = int(box[3] / self.resize_factor)
                    
                    # Calculate center in original coordinates
                    center_x = (x1 + x2) // 2
                    center_y = (y1 + y2) // 2
                    
                    detection = {
                        'track_id': track_id,
                        'class_name': self.target_classes[class_id],
                        'confidence': float(conf),
                        'bbox': (x1, y1, x2, y2),
                        'center': (center_x, center_y),
                        'center_processed': (int(box[0] + box[2])//2, int(box[1] + box[3])//2)
                    }
                    detections.append(detection)
                    
                    # Update statistics
                    self.detection_confidence_sum += conf
                    self.detection_count += 1
        
        processing_time = time.time() - start_time
        return detections, processing_time
    
    def draw_enhanced_visualizations(self, frame, detections, fps):
        """Enhanced visualization with color coding for people vs vehicles"""
        # Draw counting line (scaled to original size)
        line_y = int(self.counting_line_y / self.resize_factor)
        cv2.line(frame, (0, line_y), (self.original_width, line_y), (0, 0, 255), 4)
        cv2.putText(frame, "COUNTING LINE", (10, line_y-15), 
                   cv2.FONT_HERSHEY_SIMPLEX, 1.2, (0, 0, 255), 3)
        
        # Process each detection
        for detection in detections:
            yolo_id = detection['track_id']
    
    # Convert random ID to clean ID
            if yolo_id not in self.id_mapping:
                self.id_mapping[yolo_id] = self.next_clean_id
                self.next_clean_id += 1
            clean_id = self.id_mapping[yolo_id]
            x1, y1, x2, y2 = detection['bbox']
            center_x, center_y = detection['center']
            class_name = detection['class_name']
            confidence = detection['confidence']
            
            # Get color based on object type
            color = self.colors.get(class_name, (0, 255, 0))
            
            # Update tracking history
            track = self.track_history[yolo_id]
            track.append((center_x, center_y))
            if len(track) > self.max_track_length:
                track.pop(0)
            
            # Draw enhanced tracking path with object-specific colors
            if len(track) > 1:
                points = np.array(track).reshape((-1, 1, 2)).astype(np.int32)
                cv2.polylines(frame, [points], isClosed=False, 
                             color=color, thickness=3)
            
            # Enhanced bounding box with object-specific colors
            cv2.rectangle(frame, (x1, y1), (x2, y2), color, 3)
            cv2.rectangle(frame, (x1-2, y1-2), (x2+2, y2+2), (255, 255, 255), 1)
            
            # Professional label without emojis
            label = f"ID:{clean_id} {class_name.upper()}: {confidence:.2f}"
            label_size = cv2.getTextSize(label, cv2.FONT_HERSHEY_SIMPLEX, 0.7, 2)[0]
            cv2.rectangle(frame, (x1, y1-35), (x1+label_size[0]+10, y1), color, -1)
            cv2.putText(frame, label, (x1+5, y1-10), 
                       cv2.FONT_HERSHEY_SIMPLEX, 0.7, (255, 255, 255), 2)
            
            # Counting logic with separate counters for people and vehicles
            if len(track) >= 3:
                recent_points = track[-3:]
                y_positions = [point[1] for point in recent_points]
                
                # Check if object clearly crossed the line
                if (min(y_positions) < line_y < max(y_positions) and 
                    yolo_id not in self.counted_objects):
                    
                    self.total_count += 1
                    self.counted_objects.add(yolo_id)
                    
                    # Separate counting for people vs vehicles
                    if class_name == 'person':
                        self.people_count += 1
                    else:
                        self.vehicle_count += 1
                    
                    # Enhanced visual feedback with different colors
                    cv2.circle(frame, (center_x, center_y), 30, color, 5)
                    count_text = "PERSON COUNTED!" if class_name == 'person' else "VEHICLE COUNTED!"
                    cv2.putText(frame, count_text, (center_x-80, center_y-40), 
                               cv2.FONT_HERSHEY_SIMPLEX, 0.8, color, 3)
        
        # Enhanced statistics display with separate counters
        stats_bg_height = 160  # Increased height for more stats
        cv2.rectangle(frame, (10, 10), (450, stats_bg_height), (0, 0, 0), -1)
        cv2.rectangle(frame, (10, 10), (450, stats_bg_height), (255, 255, 255), 2)
        
        # Display enhanced statistics
        cv2.putText(frame, f"FPS: {fps:.1f}", (20, 35), 
                   cv2.FONT_HERSHEY_SIMPLEX, 1, (0, 255, 0), 2)
        cv2.putText(frame, f"👤 People: {self.people_count}", (20, 65), 
                   cv2.FONT_HERSHEY_SIMPLEX, 1, (255, 0, 255), 2)
        cv2.putText(frame, f"🚗 Vehicles: {self.vehicle_count}", (20, 95), 
                   cv2.FONT_HERSHEY_SIMPLEX, 1, (0, 255, 0), 2)
        cv2.putText(frame, f"📊 Total: {self.total_count}", (20, 125), 
                   cv2.FONT_HERSHEY_SIMPLEX, 1, (255, 255, 255), 2)
        cv2.putText(frame, f"Active: {len(detections)}", (250, 35), 
                   cv2.FONT_HERSHEY_SIMPLEX, 0.8, (0, 255, 255), 2)
        
        # Average confidence
        if self.detection_count > 0:
            avg_conf = self.detection_confidence_sum / self.detection_count
            cv2.putText(frame, f"Confidence: {avg_conf:.2f}", (250, 65), 
                       cv2.FONT_HERSHEY_SIMPLEX, 0.8, (255, 255, 0), 2)
        
        return frame
    
    def run_detection(self):
        """Main detection loop for vehicles and people"""
        print("🚗👤 Starting enhanced vehicle and people detection...")
        print("📊 New Features:")
        print("   • 👥 PEOPLE DETECTION ADDED!")
        print("   • 🎨 Color-coded detection (Magenta=People, Green=Cars, etc.)")
        print("   • 📈 Separate counters for people and vehicles")
        print("   • 🎯 Better accuracy with YOLOv8s model")
        print("   • ⚡ Optimized thresholds for better detection")
        
        frame_count = 0
        processed_frames = 0
        total_processing_time = 0
        
        while True:
            start_loop_time = time.time()
            
            ret, frame = self.video_cap.read()
            if not ret:
                print("✅ End of video reached")
                break
            
            frame_count += 1
            
            # Frame skipping for performance
            if frame_count % self.frame_skip != 0:
                # Still write the frame but don't process it
                self.out.write(frame)
                continue
            
            processed_frames += 1
            
            # Progress reporting
            if processed_frames % 50 == 0:
                avg_fps = processed_frames / total_processing_time if total_processing_time > 0 else 0
                print(f"📊 Processed {processed_frames} frames | People: {self.people_count} | Vehicles: {self.vehicle_count} | FPS: {avg_fps:.1f}")
            
            # Detection and tracking
            detections, processing_time = self.detect_and_track(frame)
            total_processing_time += processing_time
            
            # Calculate current FPS
            loop_time = time.time() - start_loop_time
            current_fps = 1.0 / loop_time if loop_time > 0 else 0
            self.fps_history.append(current_fps)
            if len(self.fps_history) > 30:
                self.fps_history.pop(0)
            
            avg_fps = sum(self.fps_history) / len(self.fps_history)
            
            # Draw visualizations
            annotated_frame = self.draw_enhanced_visualizations(frame, detections, avg_fps)
            
            # Save and display
            self.out.write(annotated_frame)
            cv2.imshow("🚀 Enhanced Vehicle & People Detection", annotated_frame)
            
            # Break on 'q' key
            if cv2.waitKey(1) & 0xFF == ord('q'):
                print("⏹️ Detection stopped by user")
                break
        
        self.cleanup()
    
    def cleanup(self):
        """Clean up resources and print final enhanced stats"""
        self.video_cap.release()
        self.out.release()
        cv2.destroyAllWindows()
        
        # Final statistics
        avg_confidence = self.detection_confidence_sum / self.detection_count if self.detection_count > 0 else 0
        avg_fps = sum(self.fps_history) / len(self.fps_history) if self.fps_history else 0
        
        print("\n" + "="*60)
        print("🎉 ENHANCED DETECTION COMPLETE - PERFORMANCE REPORT")
        print("="*60)
        print(f"👥 Total People Detected: {self.people_count}")
        print(f"🚗 Total Vehicles Detected: {self.vehicle_count}")
        print(f"📊 Grand Total Objects: {self.total_count}")
        print(f"🎯 Average Detection Confidence: {avg_confidence:.3f}")
        print(f"⚡ Average FPS: {avg_fps:.1f}")
        print(f"🚀 Model: YOLOv8s (Better accuracy)")
        print(f"✨ NEW: People detection with color coding!")
        print(f"💾 Enhanced output saved with separate counters")
        print("="*60)

# Usage - Updated class name and features
if __name__ == "__main__":
    try:
        # Now detects BOTH vehicles AND people with better accuracy!
        detector = ImprovedVehicleAndPeopleDetector("traffic.mp4", "enhanced_output.mp4")
        detector.run_detection()
    except Exception as e:
        print(f"❌ Error: {e}")
        print("💡 Make sure you have 'traffic.mp4' video file in the same folder!")
        print("💡 Or change the video path in the code above")