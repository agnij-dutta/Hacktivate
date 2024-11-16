import { ChangeEvent, useRef, useState } from "react";
import { Button } from "@/components/ui/button";
import { Upload, X } from "lucide-react";

interface FileUploadProps {
  accept?: string;
  onChange: (file: File | null) => void;
}

export function FileUpload({ accept, onChange }: FileUploadProps) {
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  const handleFileChange = (e: ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0] || null;
    setSelectedFile(file);
    onChange(file);
  };

  const handleRemoveFile = () => {
    setSelectedFile(null);
    onChange(null);
    if (inputRef.current) {
      inputRef.current.value = "";
    }
  };

  return (
    <div className="space-y-2">
      <div className="flex items-center gap-2">
        <input
          type="file"
          accept={accept}
          onChange={handleFileChange}
          className="hidden"
          ref={inputRef}
        />
        <Button
          type="button"
          variant="outline"
          onClick={() => inputRef.current?.click()}
        >
          <Upload className="w-4 h-4 mr-2" />
          Choose File
        </Button>
        {selectedFile && (
          <div className="flex items-center gap-2 text-sm">
            <span className="truncate max-w-[200px]">
              {selectedFile.name}
            </span>
            <button
              type="button"
              onClick={handleRemoveFile}
              className="text-destructive hover:text-destructive/80"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
        )}
      </div>
    </div>
  );
} 