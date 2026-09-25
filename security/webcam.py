import os
import cv2
import time
from datetime import datetime

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def capture_intruder(output_dir=None):
    """
    Silently initializes the webcam, warms up the sensor to allow exposure
    calibration, attempts to capture a clear image, and saves it.
    
    Includes a lightweight Haar Cascade face detection mechanism to verify
    if the intruder's face was captured, falling back to saving the raw capture.
    """
    if output_dir is None:
        output_dir = os.path.join(PROJECT_ROOT, "data", "forensics")
    elif not os.path.isabs(output_dir):
        output_dir = os.path.join(PROJECT_ROOT, output_dir)

    print("[WEBCAM] Triggering silent intruder capture...", flush=True)
    os.makedirs(output_dir, exist_ok=True)
    
    cap = cv2.VideoCapture(0)
    if not cap.isOpened():
        print("[WARNING] Webcam device could not be opened.", flush=True)
        return None
        
    try:
        # Warmup sensor for 5 frames to let auto-exposure/white balance calibrate
        for _ in range(5):
            cap.read()
            
        ret, frame = cap.read()
        if not ret:
            print("[WARNING] Failed to grab frame from webcam.", flush=True)
            return None
            
        # Brainstormed Upgrade: Try to detect face to ensure a valid capture
        # Load OpenCV default Haar cascade face detector
        cascade_path = cv2.data.haarcascades + 'haarcascade_frontalface_default.xml'
        face_detected = False
        
        if os.path.exists(cascade_path):
            face_cascade = cv2.CascadeClassifier(cascade_path)
            gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
            faces = face_cascade.detectMultiScale(gray, scaleFactor=1.1, minNeighbors=4, minSize=(30, 30))
            
            if len(faces) > 0:
                print(f"[WEBCAM] Successfully detected {len(faces)} face(s) in frame!", flush=True)
                face_detected = True
                # Draw bounding box for forensic visualization
                for (x, y, w, h) in faces:
                    cv2.rectangle(frame, (x, y), (x+w, y+h), (0, 0, 255), 2)
            else:
                # If no face is initially detected, try reading a few more frames
                # as the user might be moving
                for _ in range(5):
                    time.sleep(0.1)
                    ret, test_frame = cap.read()
                    if ret:
                        gray = cv2.cvtColor(test_frame, cv2.COLOR_BGR2GRAY)
                        faces = face_cascade.detectMultiScale(gray, 1.1, 4, minSize=(30, 30))
                        if len(faces) > 0:
                            frame = test_frame
                            face_detected = True
                            for (x, y, w, h) in faces:
                                cv2.rectangle(frame, (x, y), (x+w, y+h), (0, 0, 255), 2)
                            break
                            
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"intruder_{timestamp}.jpg"
        filepath = os.path.join(output_dir, filename)
        
        # Save high quality JPEG
        cv2.imwrite(filepath, frame, [int(cv2.IMWRITE_JPEG_QUALITY), 95])
        print(f"[WEBCAM] Forensic frame saved to '{filepath}' (Face Detected: {face_detected})", flush=True)
        return filepath
        
    except Exception as e:
        print(f"[ERROR] Exception during webcam capture: {e}", flush=True)
        return None
    finally:
        cap.release()
        # Explicitly destroy any cv2 windows just in case
        cv2.destroyAllWindows()

if __name__ == "__main__":
    # Test capture run
    capture_intruder()
