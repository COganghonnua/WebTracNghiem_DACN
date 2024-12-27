namespace WebTracNghiemOnline.DTO
{
    public class ExerciseHistoryDto
    {
        public string ExerciseName { get; set; }
        public int Score { get; set; }
        public DateTime StartTime { get; set; }
        public DateTime? EndTime { get; set; }
        public bool IsCompleted { get; set; }
        public string UserFullName { get; set; }
    }
}
